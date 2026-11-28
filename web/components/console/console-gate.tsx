"use client";

import { usePathname, useRouter } from "next/navigation";
import { Eye, LogOut } from "lucide-react";
import { createContext, useContext, useEffect } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { type Me, useLogout, useMe } from "@/lib/console/auth";

const MeContext = createContext<Me | null>(null);

/** The signed-in user, or null while loading / when not signed in. Gate queries on it. */
export function useConsoleUser(): Me | null {
  return useContext(MeContext);
}

/**
 * Sends visitors who are not signed in to /login. It always renders its
 * children (so the console route stays instantly navigable); pages wait for a
 * user before fetching. The API enforces access either way.
 */
export function ConsoleGate({ children }: { children: React.ReactNode }) {
  const { data: me, isLoading } = useMe();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!isLoading && me === null) router.replace(`/login?next=${encodeURIComponent(pathname)}`);
  }, [isLoading, me, pathname, router]);

  return <MeContext.Provider value={me ?? null}>{children}</MeContext.Provider>;
}

export function UserMenu() {
  const me = useConsoleUser();
  const logout = useLogout();
  const router = useRouter();
  if (!me) return <div className="ml-auto" />;
  return (
    <div className="ml-auto flex items-center gap-2 text-sm">
      {!me.can_write && (
        <Badge variant="outline" title="The demo account can look but not change anything">
          <Eye aria-hidden /> Read-only
        </Badge>
      )}
      <span className="text-muted-foreground hidden sm:inline">{me.username}</span>
      <Button
        variant="ghost"
        size="sm"
        onClick={async () => {
          await logout();
          router.replace("/login");
        }}
      >
        <LogOut aria-hidden /> Sign out
      </Button>
    </div>
  );
}
