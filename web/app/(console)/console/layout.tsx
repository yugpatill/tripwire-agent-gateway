import { AppSidebar } from "@/components/console/app-sidebar";
import { ConsoleGate, UserMenu } from "@/components/console/console-gate";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";

export default function ConsoleLayout({ children }: LayoutProps<"/console">) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <ConsoleGate>
          <header className="flex h-12 items-center gap-2 border-b px-4">
            <SidebarTrigger />
            <span className="text-muted-foreground text-sm">Tripwire console</span>
            <UserMenu />
          </header>
          <div className="min-w-0 flex-1 p-4 md:p-6">{children}</div>
        </ConsoleGate>
      </SidebarInset>
    </SidebarProvider>
  );
}
