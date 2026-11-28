"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { KeyRound } from "lucide-react";
import { useId, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api, ApiError } from "@/lib/api/client";
import { login } from "@/lib/console/auth";

export function LoginForm() {
  const router = useRouter();
  const qc = useQueryClient();
  const next = useSearchParams().get("next");
  const dest = next && next.startsWith("/console") ? next : "/console";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const userId = useId();
  const passId = useId();
  const demo = useQuery({
    queryKey: ["demo-credentials"],
    queryFn: async () => (await api.GET("/v1/auth/demo")).data ?? null,
  });

  const signIn = async (u: string, p: string) => {
    setBusy(true);
    setError(null);
    try {
      await login(u, p);
      await qc.invalidateQueries({ queryKey: ["me"] });
      router.replace(dest);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Sign-in failed");
      setBusy(false);
    }
  };

  return (
    <div className="w-full max-w-sm space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Sign in to the console</CardTitle>
          <CardDescription>Events, traces, approvals, tools and policy.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void signIn(username, password);
            }}
          >
            <div className="space-y-1">
              <label htmlFor={userId} className="text-sm font-medium">
                Email or username
              </label>
              <Input id={userId} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
            </div>
            <div className="space-y-1">
              <label htmlFor={passId} className="text-sm font-medium">
                Password
              </label>
              <Input
                id={passId}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            {error && (
              <p className="text-sm text-red-500" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
      {demo.data && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="size-4" aria-hidden /> Read-only demo account
            </CardTitle>
            <CardDescription>
              Look around without changing anything. Username <span className="text-foreground font-mono">{demo.data.username}</span>,
              password <span className="text-foreground font-mono">{demo.data.password}</span>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" className="w-full" disabled={busy} onClick={() => void signIn(demo.data!.username, demo.data!.password)}>
              Use the demo account
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
