"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, RotateCcw, Rocket } from "lucide-react";
import { useTheme } from "next-themes";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useCallback, useRef, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api/client";
import {
  deployPolicy,
  fetchMode,
  fetchPolicy,
  fetchPolicySchema,
  type PolicyErrorItem,
  type PolicyMode,
  type PolicyTestResult,
  setMode,
  testPolicy,
} from "@/lib/console/api";
import { READ_ONLY_HINT, useCanWrite } from "@/lib/console/hooks";
import { useConsoleStream } from "@/lib/console/use-console-stream";
import { cn } from "@/lib/utils";

import { ActionBadge } from "./badges";

// Monaco needs the browser: never render it on the server.
const YamlEditor = dynamic(() => import("./yaml-editor"), {
  ssr: false,
  loading: () => <Skeleton className="h-full w-full" />,
});

function policyErrors(e: unknown): PolicyErrorItem[] {
  if (e instanceof ApiError && e.status === 422 && e.detail && typeof e.detail === "object" && "errors" in e.detail) {
    return (e.detail as { errors: PolicyErrorItem[] }).errors;
  }
  return [];
}

function ModeToggle() {
  const qc = useQueryClient();
  const canWrite = useCanWrite();
  const [confirm, setConfirm] = useState(false);
  const { data } = useQuery({ queryKey: ["policy", "mode"], queryFn: fetchMode });
  const change = useMutation({
    mutationFn: (mode: PolicyMode) => setMode(mode),
    onSuccess: (r) => {
      qc.setQueryData(["policy", "mode"], r);
      toast.success(r.mode === "shadow" ? "Shadow mode on: nothing is blocked" : "Enforcing again");
      setConfirm(false);
    },
    onError: (e) => toast.error(e.message),
  });
  const shadow = data?.mode === "shadow";
  return (
    <div className={cn("flex items-center gap-3 rounded-md border px-3 py-2", shadow && "border-amber-500/60")}>
      <Switch
        id="shadow-mode"
        checked={shadow}
        disabled={!canWrite || data === undefined || change.isPending}
        onCheckedChange={(on) => (on ? setConfirm(true) : change.mutate("enforce"))}
      />
      <label htmlFor="shadow-mode" className="text-sm">
        <span className="font-medium">Shadow mode</span>{" "}
        <span className="text-muted-foreground">
          {shadow ? "on: decisions are logged, every call goes through" : "off: decisions are enforced"}
        </span>
      </label>
      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Turn on shadow mode?</DialogTitle>
            <DialogDescription>
              Tripwire will keep evaluating every call and log what it would have blocked or held, but it
              will let every call through, for all agents, until you turn it off.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
            <Button variant="destructive" disabled={change.isPending} onClick={() => change.mutate("shadow")}>
              Stop enforcing
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function TestResults({ result }: { result: PolicyTestResult }) {
  const changes = result.changes;
  const days = Math.round(result.since_hours / 24);
  return (
    <section className="space-y-2" aria-live="polite">
      <h2 className="text-lg font-semibold">Against the last {days} days</h2>
      <p className="text-muted-foreground text-sm">
        {result.replayed} recorded tool calls replayed;{" "}
        {changes.length === 0 ? "none would be decided differently." : `${changes.length} would be decided differently.`}{" "}
        Rate limits are not replayed.
        {result.skipped > 0 && ` ${result.skipped} older calls were left out: they were recorded before Tripwire stored the session state a replay needs.`}
      </p>
      {changes.length > 0 && (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead className="text-muted-foreground border-b text-left text-xs">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">When</th>
                <th scope="col" className="px-3 py-2 font-medium">Tool</th>
                <th scope="col" className="px-3 py-2 font-medium">Now</th>
                <th scope="col" className="px-3 py-2 font-medium">With this policy</th>
                <th scope="col" className="px-3 py-2 font-medium">Session</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {changes.slice(0, 200).map((c) => (
                <tr key={c.event_id}>
                  <td className="text-muted-foreground px-3 py-2 text-xs whitespace-nowrap">
                    {new Date(c.created_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs break-all">{c.tool}</td>
                  <td className="px-3 py-2">
                    <ActionBadge action={c.old_action} />
                    <div className="text-muted-foreground mt-1 font-mono text-[11px]">{c.old_rule_id ?? "no rule"}</div>
                  </td>
                  <td className="px-3 py-2">
                    <ActionBadge action={c.new_action} />
                    <div className="text-muted-foreground mt-1 font-mono text-[11px]">{c.rule_id ?? "no rule"}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <Link className="underline underline-offset-2" href={`/console/traces/${c.session_id}`}>
                      trace
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function PolicyWorkbench() {
  const qc = useQueryClient();
  const canWrite = useCanWrite();
  const { resolvedTheme } = useTheme();
  const active = useQuery({ queryKey: ["policy", "active"], queryFn: fetchPolicy });
  const schema = useQuery({ queryKey: ["policy", "schema"], queryFn: fetchPolicySchema, staleTime: Infinity });
  const [draft, setDraft] = useState<string | null>(null);
  const [errors, setErrors] = useState<PolicyErrorItem[]>([]);
  const [result, setResult] = useState<PolicyTestResult | null>(null);
  const [confirm, setConfirm] = useState(false);
  const reveal = useRef<((line: number, column: number) => void) | null>(null);

  const text = draft ?? active.data?.yaml ?? "";
  const dirty = draft !== null && draft !== active.data?.yaml;

  useConsoleStream(
    useCallback(
      (m) => {
        if (m.type === "policy.updated") void qc.invalidateQueries({ queryKey: ["policy", "active"] });
        if (m.type === "mode.updated") void qc.invalidateQueries({ queryKey: ["policy", "mode"] });
      },
      [qc],
    ),
  );

  const test = useMutation({
    mutationFn: () => testPolicy(text),
    onMutate: () => setErrors([]),
    onSuccess: setResult,
    onError: (e) => {
      setErrors(policyErrors(e));
      setResult(null);
      toast.error(e.message);
    },
  });
  const deploy = useMutation({
    mutationFn: () => deployPolicy(text),
    onMutate: () => setErrors([]),
    onSuccess: (r) => {
      toast.success(`Version ${r.version} is live`);
      setDraft(null);
      setConfirm(false);
      void qc.invalidateQueries({ queryKey: ["policy", "active"] });
    },
    onError: (e) => {
      setErrors(policyErrors(e));
      setConfirm(false);
      toast.error(e.message);
    },
  });

  if (active.isError) return <p className="text-sm text-red-500">{active.error.message}</p>;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-muted-foreground mr-auto text-sm">
          {active.data ? (
            <>
              Live: version {active.data.version} · {active.data.created_by}
              {active.data.created_at && ` · ${new Date(active.data.created_at).toLocaleString()}`}
              {dirty && <span className="text-amber-500"> · unsaved changes</span>}
            </>
          ) : (
            "Loading…"
          )}
        </p>
        <ModeToggle />
      </div>

      <div className="h-[60vh] min-h-80 overflow-hidden rounded-md border">
        {active.data && (
          <YamlEditor
            value={text}
            onChange={(v) => setDraft(v)}
            schema={schema.data ?? null}
            serverErrors={errors}
            readOnly={false}
            dark={resolvedTheme !== "light"}
            onReady={(fn) => (reveal.current = fn)}
          />
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" disabled={test.isPending || !text.trim()} onClick={() => test.mutate()}>
          <FlaskConical aria-hidden /> {test.isPending ? "Testing…" : "Test against last 7 days"}
        </Button>
        <Button disabled={!canWrite || !dirty || deploy.isPending} onClick={() => setConfirm(true)}>
          <Rocket aria-hidden /> Deploy
        </Button>
        <Button variant="ghost" disabled={!dirty} onClick={() => (setDraft(null), setErrors([]))}>
          <RotateCcw aria-hidden /> Reset
        </Button>
        {!canWrite && (
          <span className="text-muted-foreground text-xs">{READ_ONLY_HINT}: you can edit and test, not deploy.</span>
        )}
      </div>

      {errors.length > 0 && (
        <section className="space-y-1 rounded-md border border-red-500/50 p-3" aria-live="assertive">
          <h2 className="text-sm font-medium text-red-500">The policy is not valid</h2>
          <ul className="space-y-1 text-sm">
            {errors.map((e, i) => (
              <li key={i}>
                <button
                  type="button"
                  className="text-left hover:underline"
                  onClick={() => e.line && reveal.current?.(e.line, e.column ?? 1)}
                >
                  <span className="font-mono text-xs">{e.line ? `line ${e.line}:${e.column ?? 1}` : "—"}</span>{" "}
                  <span className="font-mono text-xs">{e.loc}</span> {e.message}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {result && <TestResults result={result} />}

      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy this policy?</DialogTitle>
            <DialogDescription>
              It becomes version {(active.data?.version ?? 0) + 1} and applies to the next tool call of every
              agent. The current version stays in the history.
              {!result && " You have not tested it against recorded traffic yet."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
            <Button disabled={deploy.isPending} onClick={() => deploy.mutate()}>
              {deploy.isPending ? "Deploying…" : "Deploy"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
