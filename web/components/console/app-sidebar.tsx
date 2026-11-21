"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
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

export function AppSidebar() {
  const pathname = usePathname();
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
            <SidebarMenu>
              {NAV.map(({ href, label, icon: Icon }) => (
                <SidebarMenuItem key={href}>
                  <SidebarMenuButton
                    isActive={href === "/console" ? pathname === href : pathname.startsWith(href)}
                    render={<Link href={href} />}
                  >
                    <Icon aria-hidden />
                    <span>{label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
