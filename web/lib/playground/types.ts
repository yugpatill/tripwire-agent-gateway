/** Shapes of the gateway's playground API (see docs/playground.md). */

export type Side = "unprotected" | "protected";

export interface ScenarioCard {
  id: string;
  title: string;
  summary: string;
  task: string;
  malicious: { where: string; text: string };
  attacker_goal: string;
  expected_block: { rule: string; reason: string };
  tools: string[];
  replays?: { default: "live" | "scripted" | null; available: string[] };
}

export interface CustomTask {
  id: string;
  title: string;
  task: string;
  kind: "webpage" | "email";
}

export interface ScenariosResponse {
  presets: ScenarioCard[];
  custom_tasks: CustomTask[];
  custom_max_chars: number;
  live: boolean;
  model: { provider: string; name: string } | null;
  limits: { max_steps: number; max_output_tokens: number; runs_per_ip_per_hour: number };
}

export interface StartResponse {
  run_id: string;
  mode: "live" | "scripted" | "replay";
  reason: string;
  model_source?: string;
  scenario: ScenarioCard;
}

export interface ArgLabel {
  source: string;
  trust: string;
  confidentiality: string;
}

export interface Detector {
  detector: string;
  score: number;
  spans: [number, number][];
  reason: string;
}

interface BaseEvent {
  seq: number;
  t_ms: number;
  side: Side | "run";
}

export interface RunStartedEvent extends BaseEvent {
  type: "run.started";
  run_id: string;
  mode: string;
  scenario: ScenarioCard;
  model: { provider: string; name: string; source?: string };
}

export interface ToolsListedEvent extends BaseEvent {
  type: "tools.listed";
  step: number;
  tools: string[];
}

export interface ModelTurnEvent extends BaseEvent {
  type: "model.turn";
  step: number;
  text: string;
  stop: string;
  output_tokens: number;
  tool_calls: { id: string; tool: string; args: Record<string, unknown> }[];
}

export type ToolStatus = "allowed" | "blocked" | "denied" | "withheld" | "error";

export interface ToolResultEvent extends BaseEvent {
  type: "tool.result";
  step: number;
  id: string;
  tool: string;
  args: Record<string, unknown>;
  status: ToolStatus;
  is_error: boolean;
  rule_id: string | null;
  message: string;
  content: string;
  flagged: boolean;
  detectors: Detector[];
  arg_labels?: Record<string, ArgLabel[]>;
}

export interface SideFinishedEvent extends BaseEvent {
  type: "side.finished";
  attacker_goal_reached: boolean;
  final_text: string;
  steps: number;
  stop: string;
}

export interface Verdict {
  attack_succeeded_unprotected: boolean;
  attack_succeeded_protected: boolean;
  rules_fired_protected: string[];
  expected_rule: string;
  expected_rule_fired: boolean;
}

export interface RunCompletedEvent extends BaseEvent {
  type: "run.completed";
  verdict: Verdict;
}

export interface ErrorEvent extends BaseEvent {
  type: "error";
  message: string;
}

export type RunEvent =
  | RunStartedEvent
  | ToolsListedEvent
  | ModelTurnEvent
  | ToolResultEvent
  | SideFinishedEvent
  | RunCompletedEvent
  | ErrorEvent;

export interface Environment {
  sent: { to: string; subject: string; body: string }[];
  transfers: { to_account: string; amount: number; memo: string }[];
  comments: { number: string; body: string }[];
  balance: number;
  calls: { tool: string; args: Record<string, unknown> }[];
}

export interface SideRecord {
  session_id: string | null;
  attacker_goal_reached: boolean;
  goal_calls: { tool: string; args: Record<string, unknown> }[];
  environment: Environment;
  final_text: string;
  steps: number;
  output_tokens: number;
  stop: string;
  usage?: { input_tokens: number; output_tokens: number; cost_usd: number | null };
}

export interface RunRecord {
  run_id: string;
  created_at: string;
  source: "live" | "scripted";
  model: { provider: string; name: string; scripted: boolean; source?: string };
  scenario: ScenarioCard;
  sides: Record<Side, SideRecord>;
  verdict: Verdict;
  events: RunEvent[];
  replay?: boolean;
  replay_variant?: "live" | "scripted";
  usage?: { input_tokens: number; output_tokens: number; cost_usd: number | null };
}
