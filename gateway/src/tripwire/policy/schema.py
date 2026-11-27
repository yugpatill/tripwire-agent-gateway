"""Pydantic models for the policy YAML (docs/design.md section 6.3)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tripwire.models import Action, Confidentiality, Trust


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyDefaults(_Strict):
    unknown_tool: Literal["allow", "block", "require_approval"] = "require_approval"
    # Fail closed: an engine error can never be configured to allow (fail-closed principle).
    on_engine_error: Literal["block", "require_approval"] = "block"
    classifier_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    suspicious_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _thresholds_ordered(self) -> PolicyDefaults:
        if self.suspicious_threshold > self.classifier_threshold:
            raise ValueError("suspicious_threshold must be <= classifier_threshold")
        return self


class DetectionSettings(_Strict):
    """How detector scores become a `suspicious` verdict (docs/detection.md).

    corroborated: suspicious if heuristics >= suspicious_threshold, or the classifier
      flags content that also has a weak heuristic signal (0 < heuristics). The
      classifier runs only in that weak-signal band, on the windows around the signals.
    either: suspicious if heuristics or classifier reaches suspicious_threshold; the
      classifier runs on every result (Phase 3 behaviour).
    classifier_shadow: also classify every result in the background after the response,
      for logging and the dashboard only. Never changes a decision.
    """

    combine: Literal["corroborated", "either"] = "corroborated"
    classifier_shadow: bool = False


class ToolSpec(_Strict):
    trust: Literal["trusted", "untrusted"] = "untrusted"
    confidentiality: Confidentiality = "internal"
    confidentiality_by_path: dict[str, Confidentiality] = Field(default_factory=dict)
    sink: bool = False
    risk: Literal["low", "medium", "high"] = "medium"


class RuleWhen(_Strict):
    tool: str | None = None
    sink: bool | None = None
    risk: Literal["low", "medium", "high"] | None = None
    arg: str | None = None
    label_any: list[Trust] | None = None
    context_confidentiality_at_least: Confidentiality | None = None
    session_has: Literal["suspicious"] | None = None


class RuleUnless(_Strict):
    arg_domain_in: list[str] = Field(min_length=1)


class RuleLimit(_Strict):
    max_calls: int = Field(ge=0)
    per: Literal["session"] = "session"


class Rule(_Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=100)
    when: RuleWhen = Field(default_factory=RuleWhen)
    unless: RuleUnless | None = None
    limit: RuleLimit | None = None
    action: Action
    message: str = ""


class PolicyDocument(_Strict):
    version: Literal[1]
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    tools: dict[str, ToolSpec] = Field(default_factory=dict)
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> PolicyDocument:
        seen: set[str] = set()
        for r in self.rules:
            if r.id in seen:
                raise ValueError(f"duplicate rule id: {r.id}")
            seen.add(r.id)
        return self
