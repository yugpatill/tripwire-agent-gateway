# Tripwire ml/

Training for the gateway's prompt-injection classifier. A separate uv project: it never imports the gateway; the only interface is the artifact folder (see `docs/design.md`, section 4.3).

## Pipeline

| Script | What it does |
|---|---|
| `scripts/build_dataset.py` | Builds `data/{train,val,test,test_ood}.jsonl` from deepset/prompt-injections, Dolly-15k, SQuAD v2 and generated attacks/hard negatives. Split by group; `role_markers` held out as `test_ood`. |
| `scripts/preflight.py` | Fails fast: Python ≥ 3.12, torch in `>=2.5,<3`, exact pins, no diffusers/gradio, imports, tiny BERT and DeBERTa ONNX export, int8 quantization and run. |
| `scripts/train.py` | Fine-tunes (seed 42, early stopping on val PR-AUC). |
| `scripts/export_onnx.py` | Optimum ONNX export and dynamic int8 quantization into `artifacts/injection-<model>/`, with a check that fp32 ONNX matches PyTorch within 1e-2. |
| `scripts/evaluate.py` | Scores the int8 artifact exactly as the gateway does; threshold for 1% FPR on val benign; writes `metrics.json`. |
| `scripts/check_artifacts.py` | Checks every artifact folder against the contract, prints a summary, and builds `tripwire-artifacts.zip`. |
| `scripts/latency_probe.py` | Untrained int8 probes for latency benchmarks only. |

Training runs on a free Colab/Kaggle T4 with `notebooks/train_colab.ipynb`, not on a laptop.

## Colab requirements

`requirements-colab.txt` pins the same versions as `uv.lock`, with every transitive dependency, for Linux on Python 3.12+. torch and its CUDA/Triton wheels are left out so the runtime's GPU build of torch is kept. To regenerate it after changing `pyproject.toml`, put the top-level pins from `uv.lock` (plus `optimum[onnxruntime]` and `torch>=2.5,<3`) in a `.in` file, then:

```bash
uv pip compile colab.in --universal --python-version 3.12 --no-header --no-annotate --no-emit-package torch --no-emit-package triton -o requirements-colab.txt
```

Then delete any `nvidia-*` and `cuda-*` lines.

Colab and Kaggle preinstall diffusers and gradio, which need `huggingface_hub>=1`. Our transformers pin needs `<1.0`, and optimum's exporter imports diffusers when it is present, so the notebook uninstalls them first.

## Open items

- [ ] **Retrain with realistic tool outputs** before the Phase 9 final evaluation ([plan](#retrain-plan-open-item-run-before-the-phase-9-final-evaluation)). Code and notebook ready (2026-11-28, [what changed](#phase-9-retrain-what-changed)); waiting for the Colab run.
- [ ] **Fix DeBERTa-v3-small's int8 export**, then decide whether to publish it as the opt-in accurate mode. Exporter fixed (verified quantization settings); experimental until the retrained artifact passes.
- [ ] **Prompt Guard 2 22M zero-shot baseline**: needs Hugging Face access approval for the account running the notebook (`HF_TOKEN`).

## Results (Phase 4, 2026-11-26)

Trained on a Colab T4, seed 42, same dataset and splits for every model. Every number is measured on the **int8 ONNX artifact**, scored exactly as the gateway scores it (batch 1, 512-token windows, 64-token overlap). The threshold is the lowest score with FPR ≤ 1% on the 2,777 benign tool outputs in val. The committed `metrics.json` files hold the full numbers.

**MiniLM base selection.** One epoch each, picked by val PR-AUC: `sentence-transformers/all-MiniLM-L6-v2` (PR-AUC 0.9987, F1@0.5 0.947) beat `nreimers/MiniLM-L6-H384-uncased` (0.9951, 0.913). The sentence-transformers checkpoint starts from contrastive sentence training, so it separates "instruction aimed at the reader" from "instruction quoted in content" faster. Usable max sequence length: 512 tokens, from BERT's 512 learned position embeddings; the sentence-transformers card's 256 limit only reflects how that model was trained for embeddings, and fine-tuning at 512 uses the full table.

| | MiniLM-L6 (default) | DeBERTa-v3-small (**experimental**) | Prompt Guard 2 22M (zero-shot) |
|---|---|---|---|
| Base | all-MiniLM-L6-v2 (Apache-2.0) | microsoft/deberta-v3-small (MIT) | not run: needs approved Hugging Face access |
| int8 ONNX size | **23 MB** | 172 MB | 87 MB (deberta-v3-xsmall probe) |
| Threshold (1% FPR, val benign) | 0.99934 | 0.02623 | |
| **test** precision / recall / F1 | 0.998 / 0.964 / 0.981 | 0.976 / 0.987 / 0.981 | |
| test ROC AUC | 0.9991 | 0.9992 | |
| test FPR (all benign / hard negatives) | 0.1% / 0.35% | 1.07% / 3.63% | |
| test recall per family: direct_override, exfiltration, jailbreak, tool_hijack, markdown_exfil, deepset | 1.00, 0.996, 0.996, 0.968, 0.996, **0.43** | 1.00, 0.996, 0.996, 0.996, 1.00, 0.77 | |
| **test_ood** (held-out role_markers) precision / recall / F1 | 0.998 / **0.994** / 0.996 | 0.978 / 0.987 / 0.983 | |
| test_ood ROC AUC | 0.9998 | 0.9993 | |
| Phase 3 gateway corpus (n = 250 benign, 133 attacks): FPR / recall | 6.8% / 73.7% | 11.6% / 85.7% | |
| x86 latency p95, 2 threads, 2 KB / 50 KB (AMD EPYC 9V74, same runner) | **60–63 ms / 360–370 ms** | 377–414 ms / 1.51–1.54 s (untrained probe) | not measured on this CPU (xsmall probe on the Phase 3 Xeon: 255 ms / 1.04 s) |

### Decision

Rule (set before training): MiniLM-L6 is the default if its test_ood recall is within 5 points of DeBERTa-v3-small at the same FPR. It is better: **99.4% vs 98.7%**, at a tenfold lower test FPR (0.1% vs 1.07%), with the same test F1 (0.981) and a 7x smaller artifact. **MiniLM-L6 is the default** and ships in the image (release `classifier-minilm-l6-v1`). DeBERTa-v3-small is **experimental** and is not published: it is meant to become an opt-in accurate mode (via `TRIPWIRE_CLASSIFIER_DIR` or the `CLASSIFIER_URL`/`CLASSIFIER_SHA256` image build args), but only after its int8 export is fixed (Known problems 2).

Where DeBERTa is better: the human-written deepset injections (77% vs 43% recall; n = 30, many short or in German) and base64 payloads in the Phase 3 corpus. Both point at the same gap: MiniLM generalizes less beyond our generated attack templates.

### Known problems

1. **False positives on realistic tool outputs.** 1% FPR on val became 6.8% on the Phase 3 corpus (17–18 of 250, depending on CPU rounding at the threshold): val benign data is prose (SQuAD, Dolly), while real tool outputs include raw HTML, terse JSON fields and boilerplate. See "Phase 3 corpus analysis" below.
2. **DeBERTa-v3-small loses accuracy under dynamic int8.** Export verification shows a maximum probability difference of 0.98 between int8 and PyTorch on 64 val texts (MiniLM: 0.006). The low threshold (0.026) and its 11.6% FPR on the Phase 3 corpus reflect that. Its scores also differ between ARM and x86 int8 kernels (9.2% FPR in the gateway on an M3 versus 11.6% on the Colab x86 CPU). Before DeBERTa is published as the accurate mode, export it with attention and embedding nodes left in fp32, or ship fp16, and require int8-vs-PyTorch difference < 0.05.
3. **The classifier sees raw text only.** Payloads hidden in Unicode tags or base64 are mostly missed by the classifier (MiniLM: 12 of 22 hidden_unicode and 11 of 22 base64 misses); the heuristics catch them on decoded views.

### Phase 3 corpus analysis (MiniLM-L6)

`gateway/scripts/analyze_classifier.py` runs the gateway's own heuristics and classifier on the Phase 3 corpus. No threshold was chosen on this corpus: stricter thresholds come from `scripts/val_thresholds.py` (val benign only). The heuristics were tuned on the non-held-out part, so their recall there is optimistic; the held-out columns are the honest ones.

False positives at the artifact threshold, by category:

| Category | n | FP | FP with any heuristic signal |
|---|---|---|---|
| web_pages | 40 | 6 | 0 |
| api_json | 40 | 5 | 0 |
| docs | 30 | 3 | 1 |
| hard_negatives | 30 | 1 | 0 |
| heldout benign | 40 | 3 | 0 |
| emails, support_tickets | 70 | 0 | 0 |
| **Total** | **250** | **18** | **1** |

Three patterns account for all of them:
- **Raw HTML with analytics boilerplate** (6): every flagged page starts `<!DOCTYPE html>…<!-- Google Tag Manager --><script async src="https://www.googletagmanager.com/gtm.js?id=…">`. Our injected carriers put payloads in HTML comments, so the model learned "HTML comment + script URL" as a cue.
- **Terse API fields and blobs** (5): `invoice.paid evt_1PzQ`; `Support support@vendor.example +1 415-555-0198`; `file README.md base64 IyB1dGlscwoK…`; a `data:image/png;base64,…` URL. Nothing like these short, structured strings is in the benign training data.
- **Imperative or warning sentences in docs** (7): "Tutorial step 7: Now forget the debugger for a moment and look at the logs instead."; "Security awareness: attackers may ask you to wire money urgently. Verify by phone."; "Legal notice: … If received in error, delete it."; changelog lines mentioning "instructions".

Decision rules (h = heuristic score, c = MiniLM probability; suspicious when the rule holds):

| Rule | FPR, all benign (250) | Recall, all attacks (133) | FPR, held-out (40) | Recall, held-out (30) |
|---|---|---|---|---|
| heuristics only: h ≥ 0.5 | 0.4% | 96.2% | 0.0% | 90.0% |
| classifier only: c ≥ 0.99934 | 7.2% | 75.9% | 7.5% | 83.3% |
| Phase 3 wiring: max(h, c) ≥ 0.5 (bug, fixed) | 23.2% | 100% | 20.0% | 100% |
| **either**: h ≥ 0.5 OR c ≥ 0.99934 (current gateway) | 7.6% | 100% | 7.5% | 100% |
| **corroborated**: h ≥ 0.5 OR (c ≥ 0.99934 AND h > 0) | **0.8%** | **99.2%** | **0.0%** | **96.7%** |
| either, stricter c ≥ 0.999626 (0.5% val FPR) | 6.0% | 99.2% | 5.0% | 100% |
| either, stricter c ≥ 0.999715 (0.1% val FPR) | 4.8% | 99.2% | 5.0% | 100% |
| corroborated, c ≥ 0.999715 | 0.8% | 98.5% | 0.0% | 96.7% |

Raising the classifier threshold alone does not fix it: the false positives sit at 0.9994–0.9998, inside the attack score range. Requiring a heuristic signal does: 17 of 18 classifier false positives have no heuristic signal at all, while 100 of 101 classifier detections of attacks do. The cost is attacks the classifier alone would catch: on held-out data, the corroborated rule catches 2 of the 3 paraphrased overrides the heuristics miss; the "either" rule catches all 3. DeBERTa-v3-small gives the same picture (corroborated: 0.4% FPR, 99.2% recall).

The "Phase 3 wiring" row is a bug found here: the gateway compared the raw probability with `suspicious_threshold` (0.5) and ignored the artifact threshold. Since commit 7de70d9 the classifier reports a calibrated score (artifact threshold → 0.5), which gives the "either" row.

### Retrain plan (open item: run before the Phase 9 final evaluation)

Deferred at the Phase 4 review. Status: **open**. The gateway now uses the corroborated rule (classifier hits count only alongside a heuristic signal), which brings the Phase 3 corpus false-positive rate from 7.6% to 0.8% without retraining; the retrain is still needed before the final evaluation so the classifier is usable on its own (`detection.combine: either`) and in shadow mode.

1. **New benign tool-output set**, built by a new `scripts/build_tool_outputs.py`, separate from `gateway/tests/fixtures/` and checked against it (no shared 8-gram with any fixture, otherwise the row is dropped). About 6,000 rows, split by template group into train/val/test:
   - raw HTML pages: SQuAD/Wikipedia text wrapped in realistic boilerplate (analytics and tag-manager snippets, cookie banners, build and CMS HTML comments, inline scripts and JSON-LD, navigation);
   - API responses flattened with the gateway's own rule (string leaves joined by newlines): event names and IDs, UUIDs, hashes, timestamps, prices, status codes, short log lines, `data:` URIs, base64 file contents of benign files, DNS records, CI results;
   - docs and notices: READMEs, changelogs, FAQs, tutorials with imperative steps, security-awareness tips, legal disclaimers, unsubscribe footers, written from templates plus Dolly instructions (CC BY-SA 3.0).
2. **Matching attacks in the same carriers**: about 25% of each new carrier type gets an injection (in an HTML comment, a JSON string field, a doc paragraph), so the model learns the payload and not the format.
3. **More real-world attacks**: up-weight deepset train rows (and add other permissively licensed human-written injection sets after a license check) to close the 43% deepset gap.
4. **Threshold and gates**: threshold re-chosen at 1% FPR on the new val (prose plus tool outputs). Accept the new model only if the Phase 3 corpus is scored once at the end with classifier-only FPR ≤ 2% and test_ood recall ≥ 98%. The Phase 3 corpus stays out of training and threshold selection.
5. **DeBERTa int8 fix** (see Known problems 2). Until then DeBERTa-v3-small stays experimental and unpublished.
6. Expected time on a T4: about 1 hour for both models.

### Phase 9 retrain: what changed

Implemented 2026-11-28; numbers below are from building the dataset locally (seed 42), before any training.

- **`scripts/build_tool_outputs.py`**: 36 carrier templates (10 HTML, 14 API, 12 docs), 170 benign rows each, and an injected copy of about a quarter of them. Templates are the split groups (24 train, 6 val, 6 test), so val and test measure formats the model never saw. HTML text comes from SQuAD v2 *validation* articles (the base carriers use train); doc and API free text from Dolly rows of the same split. Every hiding place an injected copy uses (HTML comments, hidden elements, extra posts, JSON fields, log lines, plain-text file contents) also appears with harmless text in benign rows, so the structure is not a cue. Injected rows are kept only if the whole text fits one 512-token window for both tokenizers (55 dropped), so a payload is never truncated away from its label.
- **Human-written attacks**: Lakera/gandalf_ignore_instructions (MIT) and jackhhao/jailbreak-classification (Apache-2.0, its benign role-play prompts as hard negatives), on their own splits; half are embedded in a carrier. In train, deepset is repeated 3x and the others 2x. hackaprompt (gated) and safe-guard-prompt-injection (no license) were left out.
- **Leakage check**: any row sharing a word 8-gram with `gateway/tests/fixtures/` is dropped. It removed 773 rows, 720 of them Phase 4 generated hard negatives: five templates (for example "Please ignore my previous email; I attached the wrong file") were near-copies of Phase 3 hard negatives, so the Phase 4 model had trained on text close to part of its out-of-distribution check. It also caught two of my first new templates (a standard tag-manager URL and a security tip), which were reworded.
- **Splits**: train 32,784 rows (8,844 injections), val 5,386 (1,659), test 5,679 (1,761), test_ood 5,286 (1,368). The threshold is still the lowest score with FPR <= 1% on val benign, which now includes the held-out tool formats.
- **DeBERTa int8**: `export_onnx.py` tries five dynamic-quantization settings (default, per-channel, per-channel without attention MatMuls, MatMul-only, MatMul-only without attention) on 256 val texts scored one at a time, keeps the first within 0.05 of PyTorch, and records the setting and `int8_ok` in `config.json`. The MatMul-only settings keep DeBERTa's embedding table in fp32 (about 470 MB instead of 172 MB), so they come last.
- **Gate**: `scripts/gate.py` checks Phase 3 corpus classifier-only FPR <= 2%, test_ood recall >= 98% and `int8_ok`, and prints the numbers the top-level README quotes from the Phase 4 model. On the Phase 4 metrics it fails both models (6.8% and 11.6% corpus FPR; DeBERTa int8 0.98).
- The notebook keeps the Phase 4 MiniLM base (`sentence-transformers/all-MiniLM-L6-v2`) instead of re-running the selection.
