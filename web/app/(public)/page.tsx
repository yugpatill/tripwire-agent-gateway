import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";

export default function HomePage() {
  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col items-center justify-center gap-6 px-6 py-24 text-center">
      <ShieldCheck className="size-12 text-green-500" aria-hidden />
      <h1 className="text-4xl font-semibold tracking-tight">Tripwire</h1>
      <p className="text-muted-foreground text-lg">
        A security gateway for LLM agents. The attack playground is coming soon.
      </p>
      <Button nativeButton={false} render={<Link href="/console" />}>Open operator console</Button>
    </main>
  );
}
