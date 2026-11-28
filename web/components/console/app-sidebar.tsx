"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Suspense } from "react";
import {
  Activity,
  FlaskConical,
  GitBranch,
  LayoutDashboard,
  ShieldCheck,
  ShieldQuestion,
  FileCode2,
  Wrench,
} from "lucide-react";

import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

const NAV = [
  { href: "/console", label: "Overview", icon: LayoutDashboard },
  { href: "/console/events", label: "Events", icon: Activity },
  { href: "/console/traces", label: "Traces", icon: GitBranch },
  { href: "/console/approvals", label: "Approvals", icon: ShieldQuestion },
  { href: "/console/tools", label: "Tools", icon: Wrench },
  { href: "/console/policy", label: "Policy", icon: FileCode2 },
  { href: "/console/evals", label: "Evaluations", icon: FlaskConical },
] as const;

function NavMenu({ pathname }: { pathname: string | null }) {
  return (
    <SidebarMenu>
      {NAV.map(({ href, label, icon: Icon }) => (
        <SidebarMenuItem key={href}>
          <SidebarMenuButton
            isActive={pathname !== null && (href === "/console" ? pathname === href : pathname.startsWith(href))}
            render={<Link href={href} />}
          >
            <Icon aria-hidden />
            <span>{label}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      ))}
    </SidebarMenu>
  );
}

function ActiveNavMenu() {
  return <NavMenu pathname={usePathname()} />;
}

export function AppSidebar() {
  return (
    <Sidebar>
      <SidebarHeader>
        <Link href="/" className="flex items-center gap-2 px-2 py-1.5 font-semibold">
          <ShieldCheck className="size-5 text-green-500" aria-hidden />
          Tripwire
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Operator console</SidebarGroupLabel>
          <SidebarGroupContent>
            {/* The current path is request data: highlight inside Suspense. */}
            <Suspense fallback={<NavMenu pathname={null} />}>
              <ActiveNavMenu />
            </Suspense>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
