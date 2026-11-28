import Link from "next/link";

import { ShieldCheck } from "lucide-react";

export function SiteHeader() {
  return (
    <header className="border-b">
      <nav className="mx-auto flex h-14 w-full max-w-7xl items-center gap-6 px-4 md:px-6" aria-label="Main">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="size-5 text-green-500" aria-hidden />
          Tripwire
        </Link>
        <div className="text-muted-foreground ml-auto flex items-center gap-5 text-sm">
          <Link href="/#scenarios" className="hover:text-foreground">
            Playground
          </Link>
          <a href="https://github.com/yugpatill/tripwire-agent-gateway" className="hover:text-foreground">
            GitHub
          </a>
          <Link href="/console" prefetch={false} className="hover:text-foreground">
            Console
          </Link>
        </div>
      </nav>
    </header>
  );
}
