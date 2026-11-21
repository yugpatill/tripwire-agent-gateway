# Policy condition test coverage

Maps every condition in the policy schema (spec section 4.3) to the tests that exercise it. `test_policy_coverage_table.py` fails CI if a schema condition has no row here or if a listed test no longer exists.

Files: `E` = `tests/unit/test_policy_eval.py` (rule evaluator, synthetic facts), `G` = `tests/unit/test_engine.py` (full engine with the demo policy), `T` = `tests/unit/test_taint_evasion.py`, `I` = `tests/integration/test_api_live.py` (HTTP + Postgres + Redis).

| Condition | Tests |
|---|---|
| `tool` | E `test_tool_exact_and_glob`, E `test_when_keys_combine_with_and`, G `test_untrusted_recipient_blocked`, I `test_untrusted_recipient_blocked_over_http` |
| `sink` | E `test_sink_condition`, E `test_when_keys_combine_with_and`, E `test_unknown_tool_treated_as_high_risk_sink`, G `test_session_has_suspicious_requires_approval_for_sinks` |
| `risk` | E `test_risk_condition`, E `test_when_keys_combine_with_and`, E `test_unknown_tool_treated_as_high_risk_sink` |
| `arg` | E `test_arg_condition_requires_arg_present`, E `test_label_any_scoped_to_arg`, G `test_redact_action_masks_target_arg` |
| `label_any` | E `test_label_any_scoped_to_arg`, E `test_label_any_without_arg_checks_all_args`, E `test_label_any_does_not_match_trusted`, E `test_label_any_matches_untrusted_origin`, G `test_untrusted_recipient_blocked`, G `test_paraphrased_unknown_recipient_is_untrusted_origin`, G `test_untrusted_payee_blocked`, T `test_url_encoded_address_caught_by_instruction_origin` |
| `context_confidentiality_at_least` | E `test_context_confidentiality_at_least`, G `test_secret_context_blocks_outside_fetch_but_allows_allowlisted`, G `test_confidential_context_external_recipient_needs_approval` |
| `session_has` | E `test_session_has_suspicious`, G `test_session_has_suspicious_requires_approval_for_sinks` |
| `unless.arg_domain_in` | E `test_unless_domain_allowlist`, E `test_unless_without_domains_does_not_exempt`, E `test_unless_without_arg_checks_all_args`, E `test_domain_allowed_semantics`, G `test_secret_context_blocks_outside_fetch_but_allows_allowlisted`, G `test_confidential_context_external_recipient_needs_approval` |
| `limit` | E `test_limit_triggers_after_max_calls`, E `test_limit_counts_only_matching_calls`, G `test_transfer_rate_limit`, G `test_limit_counts_are_per_session` |
| shadow mode | G `test_shadow_mode_logs_but_does_not_block`, G `test_global_shadow_mode`, G `test_shadow_mode_redact_returns_log_only_without_redaction`, G `test_shadow_mode_leaves_allow_untouched` |
| `defaults.unknown_tool` | E `test_unknown_tool_default`, G `test_unknown_tool_requires_approval` |
| `defaults.on_engine_error` | G `test_missing_policy_fails_closed`, G `test_store_exception_fails_closed`, G `test_recorder_exception_fails_closed_without_raising` |
| `tools.<name>.confidentiality_by_path` | E `test_confidentiality_by_path`, G `test_result_labels_and_path_confidentiality` |
| `tools.<name>.trust` | G `test_result_labels_and_path_confidentiality`, G `test_address_from_trusted_tool_is_allowed_and_not_untrusted_origin` |
| action precedence | E `test_precedence_block_beats_earlier_approval`, E `test_precedence_approval_beats_redact` |

`defaults.classifier_threshold` and `defaults.suspicious_threshold` are validated in Phase 2 (`test_thresholds_must_be_ordered`) and used by the Phase 3 detectors.
