"""Parse and validate policy YAML with line/column error locations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from tripwire.policy.schema import PolicyDocument


@dataclass(frozen=True, slots=True)
class PolicyErrorDetail:
    loc: str
    message: str
    line: int | None  # 1-based
    column: int | None  # 1-based


class PolicyError(Exception):
    def __init__(self, errors: list[PolicyErrorDetail]) -> None:
        self.errors = errors
        super().__init__("; ".join(f"{e.loc}: {e.message}" for e in errors))


def _locate(node: yaml.Node | None, loc: tuple[int | str, ...]) -> yaml.Node | None:
    """Walk the YAML node tree along a pydantic error location."""
    for part in loc:
        if node is None:
            return None
        if isinstance(node, yaml.MappingNode):
            nxt = None
            for k, v in node.value:
                if isinstance(k, yaml.ScalarNode) and k.value == str(part):
                    nxt = v
                    break
            if nxt is None:
                return node
            node = nxt
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int):
            if part >= len(node.value):
                return node
            node = node.value[part]
        else:
            return node
    return node


def parse_policy(text: str) -> PolicyDocument:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        data: Any = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        raise PolicyError(
            [
                PolicyErrorDetail(
                    loc="",
                    message=str(exc.problem or exc),
                    line=mark.line + 1 if mark else None,
                    column=mark.column + 1 if mark else None,
                )
            ]
        ) from exc
    if not isinstance(data, dict):
        raise PolicyError([PolicyErrorDetail("", "policy must be a YAML mapping", 1, 1)])
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        details: list[PolicyErrorDetail] = []
        for err in exc.errors():
            node = _locate(root, tuple(err["loc"]))
            mark = node.start_mark if node is not None else None
            details.append(
                PolicyErrorDetail(
                    loc=".".join(str(p) for p in err["loc"]),
                    message=err["msg"],
                    line=mark.line + 1 if mark else None,
                    column=mark.column + 1 if mark else None,
                )
            )
        raise PolicyError(details) from exc


def load_policy_file(path: str | Path) -> tuple[PolicyDocument, str]:
    text = Path(path).read_text(encoding="utf-8")
    return parse_policy(text), text
