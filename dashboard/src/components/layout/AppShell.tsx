import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  FileClock,
  LayoutDashboard,
  Laptop,
  ScrollText,
  ShieldAlert,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { BackendStatus } from "@/components/layout/BackendStatus";

/** The seven console sections required by spec §29. */
const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/endpoints", label: "Endpoints", icon: Laptop },
  { to: "/users", label: "Users", icon: Users },
  { to: "/sessions", label: "Sessions", icon: Activity },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/policies", label: "Policies", icon: ScrollText },
  { to: "/audit", label: "Audit", icon: FileClock },
] as const;

export function AppShell() {
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 border-r bg-card md:flex md:flex-col">
        <div className="border-b px-5 py-4">
          <div className="text-base font-semibold tracking-wide">NETRA</div>
          <div className="text-xs text-muted-foreground">
            Security Operations
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-0.5 p-2">
          {NAV.map(({ to, label, icon: Icon, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest ? rest.end : false}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent font-medium text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                )
              }
            >
              <Icon className="size-4" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t p-3">
          <BackendStatus />
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <Outlet />
      </main>
    </div>
  );
}
