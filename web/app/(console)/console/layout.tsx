import { AppSidebar } from "@/components/console/app-sidebar";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";

// Auth gate is added in Phase 8; for now the console shell renders unauthenticated.
export default function ConsoleLayout({ children }: LayoutProps<"/console">) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-12 items-center gap-2 border-b px-4">
          <SidebarTrigger />
          <span className="text-muted-foreground text-sm">Tripwire console</span>
        </header>
        <div className="flex-1 p-6">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  );
}
