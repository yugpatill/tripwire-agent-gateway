"""DeBERTa prompt-injection classifier, ONNX Runtime on CPU.

Loads the artifact folder produced by ``ml/`` (path from TRIPWIRE_CLASSIFIER_DIR):

    model.int8.onnx   inputs: input_ids, attention_mask (int64); output: logits [batch, n_labels]
    tokenizer.json    Hugging Face `tokenizers` format
    config.json       {"max_length": int, "threshold": float, "labels": ["benign", "injection"]}

If the folder is missing or invalid the classifier is *unavailable*: a warning is
logged once and the pipeline runs on heuristics alone. Long inputs are split
into windows of ``max_length`` tokens with a 64-token overlap; the document score
is the maximum window score.

The reported score is *calibrated*: the artifact's ``threshold`` (chosen in ``ml/``
for 1% FPR on benign tool outputs) maps to 0.5, the policy's default
``suspicious_threshold``, and the probability is rescaled linearly on either side
(see ``calibrate``). Fine-tuned models put almost every score near 0 or 1, so
comparing the raw probability with 0.5 would ignore the threshold the artifact
was evaluated at.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import structlog

from tripwire.models import DetectorResult

log = structlog.get_logger(__name__)

OVERLAP_TOKENS = 64
# Long outputs: classify at most the first/last HEAD_TAIL_WINDOWS windows plus any
# window that overlaps a weak heuristic signal (see docs/limitations.md).
MAX_FULL_WINDOWS = 8
HEAD_TAIL_WINDOWS = 4
# At most this many extra "focus" windows, taken from the strongest signals first,
# so scattered weak signals in a long benign document cannot pull in every window.
MAX_FOCUS_WINDOWS = 4
# A "focus" span longer than this fraction of the text (e.g. a whole-document
# invisible-character signal) does not localize anything and is ignored.
MAX_FOCUS_FRACTION = 0.5
MODEL_FILE = "model.int8.onnx"
TOKENIZER_FILE = "tokenizer.json"
CONFIG_FILE = "config.json"
POSITIVE_LABELS = ("injection", "malicious", "jailbreak", "attack", "1")


@dataclass(frozen=True, slots=True)
class ClassifierConfig:
    max_length: int
    threshold: float
    labels: list[str]
    positive_index: int


def _load_config(path: Path) -> ClassifierConfig:
    raw: dict[str, Any] = json.loads(path.read_text())
    labels = [str(x) for x in raw["labels"]]
    positive = next(
        (i for i, lab in enumerate(labels) if lab.lower() in POSITIVE_LABELS), len(labels) - 1
    )
    max_length = int(raw["max_length"])
    if max_length <= OVERLAP_TOKENS + 2:
        raise ValueError(f"max_length {max_length} too small for {OVERLAP_TOKENS}-token overlap")
    return ClassifierConfig(max_length, float(raw["threshold"]), labels, positive)


def calibrate(p: float, threshold: float) -> float:
    """Map p(injection) so that ``threshold`` lands on 0.5.

    [0, t] maps linearly to [0, 0.5] and [t, 1] to [0.5, 1].
    """
    if p >= threshold:
        return 0.5 + 0.5 * (p - threshold) / (1.0 - threshold) if threshold < 1.0 else 1.0
    return 0.5 * p / threshold if threshold > 0.0 else 0.5


class InjectionClassifier:
    def __init__(self, model_dir: str | Path | None, intra_op_threads: int = 2) -> None:
        self.model_dir = Path(model_dir) if model_dir else None
        self.available = False
        self.reason = ""
        self.config: ClassifierConfig | None = None
        self._session: Any = None
        self._tokenizer: Any = None
        self._lock = threading.Lock()
        self._load(intra_op_threads)

    def _load(self, threads: int) -> None:
        d = self.model_dir
        missing = (
            "TRIPWIRE_CLASSIFIER_DIR not set"
            if d is None
            else next(
                (
                    f"{d / f} not found"
                    for f in (MODEL_FILE, TOKENIZER_FILE, CONFIG_FILE)
                    if not (d / f).is_file()
                ),
                None,
            )
        )
        if missing:
            self.reason = missing
            log.warning("classifier.unavailable", reason=missing, fallback="heuristics only")
            return
        assert d is not None
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer

            self.config = _load_config(d / CONFIG_FILE)
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = threads
            opts.inter_op_num_threads = 1
            self._session = ort.InferenceSession(
                str(d / MODEL_FILE), sess_options=opts, providers=["CPUExecutionProvider"]
            )
            tok = Tokenizer.from_file(str(d / TOKENIZER_FILE))
            tok.no_truncation()
            tok.no_padding()
            self._tokenizer = tok
            self._input_names = {i.name for i in self._session.get_inputs()}
        except Exception as exc:  # a broken artifact must not take the gateway down
            self.reason = f"failed to load: {exc!r}"
            self._session = None
            log.warning("classifier.unavailable", reason=self.reason, fallback="heuristics only")
            return
        self.available = True
        log.info("classifier.loaded", dir=str(d), max_length=self.config.max_length)

    def _windows(self, ids: list[int]) -> list[list[int]]:
        assert self.config is not None
        tok = self._tokenizer
        # Reserve room for special tokens added by the post-processor (e.g. [CLS] ... [SEP]).
        specials = tok.num_special_tokens_to_add(False)
        body = self.config.max_length - specials
        return [ids[s : s + body] for s in self._window_starts(len(ids))]

    def _window_starts(self, n_tokens: int) -> list[int]:
        assert self.config is not None
        body = self.config.max_length - self._tokenizer.num_special_tokens_to_add(False)
        if n_tokens <= body:
            return [0]
        stride = body - OVERLAP_TOKENS
        return list(range(0, max(n_tokens - OVERLAP_TOKENS, 1), stride))

    @staticmethod
    def select_windows(
        char_ranges: list[tuple[int, int]],
        focus: list[tuple[int, int]],
        text_len: int,
    ) -> list[int]:
        """Indices of windows to classify: all of them for short inputs; for long
        ones the first and last HEAD_TAIL_WINDOWS plus up to MAX_FOCUS_WINDOWS windows
        overlapping focus spans (strongest first). At most 12 windows in total."""
        n = len(char_ranges)
        if n <= MAX_FULL_WINDOWS:
            return list(range(n))
        chosen = set(range(HEAD_TAIL_WINDOWS)) | set(range(n - HEAD_TAIL_WINDOWS, n))
        extra = 0
        # `focus` is ordered strongest signal first.
        for fs, fe in focus:
            if extra >= MAX_FOCUS_WINDOWS:
                break
            if fe - fs > MAX_FOCUS_FRACTION * text_len:
                continue
            for i, (s, e) in enumerate(char_ranges):
                if s < fe and fs < e and i not in chosen and extra < MAX_FOCUS_WINDOWS:
                    chosen.add(i)
                    extra += 1
        return sorted(chosen)

    def score(self, text: str, focus: list[tuple[int, int]] | None = None) -> DetectorResult:
        """p(injection) as the max over windows. `focus` spans (e.g. weak heuristic
        hits) decide which middle windows are classified for long inputs."""
        if not self.available or not text.strip():
            return DetectorResult(
                detector="classifier", score=0.0, spans=[], reason=self.reason or "empty input"
            )
        assert self.config is not None
        enc = self._tokenizer.encode(text, add_special_tokens=False)
        ids: list[int] = enc.ids
        offsets: list[tuple[int, int]] = enc.offsets
        if not ids:
            return DetectorResult(detector="classifier", score=0.0, spans=[], reason="no tokens")
        body = self.config.max_length - self._tokenizer.num_special_tokens_to_add(False)
        starts = self._window_starts(len(ids))
        ranges = [(offsets[st][0], offsets[min(st + body, len(ids)) - 1][1]) for st in starts]
        selected = self.select_windows(ranges, focus or [], len(text))
        best, best_span = 0.0, ranges[0]
        for i in selected:
            st = starts[i]
            input_ids = self._with_specials(ids[st : st + body])
            feed = {
                "input_ids": np.asarray([input_ids], dtype=np.int64),
                "attention_mask": np.ones((1, len(input_ids)), dtype=np.int64),
            }
            if "token_type_ids" in self._input_names:
                feed["token_type_ids"] = np.zeros((1, len(input_ids)), dtype=np.int64)
            with self._lock:
                logits = self._session.run(None, feed)[0][0]
            probs = np.exp(logits - logits.max())
            probs /= probs.sum()
            p = float(probs[self.config.positive_index])
            if p > best:
                best, best_span = p, ranges[i]
        # Floor rather than round, so a probability just below the artifact threshold
        # can never be reported as 0.5.
        calibrated = int(calibrate(best, self.config.threshold) * 1e6) / 1e6
        return DetectorResult(
            detector="classifier",
            score=calibrated,
            spans=[best_span] if best > 0 else [],
            reason=(
                f"max window p(injection)={best:.6f} (artifact threshold "
                f"{self.config.threshold}); classified {len(selected)}/{len(starts)} windows"
            ),
        )

    def _with_specials(self, window: list[int]) -> list[int]:
        """Wrap a window in the model's sequence tokens ([CLS] ... [SEP] for DeBERTa)."""
        cls_id = self._tokenizer.token_to_id("[CLS]")
        sep_id = self._tokenizer.token_to_id("[SEP]")
        if cls_id is not None and sep_id is not None:
            return [cls_id, *window, sep_id]
        return list(window)
