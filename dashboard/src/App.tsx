import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Overview } from "@/pages/Overview";
import {
  Audit,
  Endpoints,
  Incidents,
  Policies,
  Sessions,
  Users,
} from "@/pages/Placeholders";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A stale risk figure is misleading in an operations console, so cached
      // values are never served as fresh.
      staleTime: 0,
      refetchOnWindowFocus: true,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Overview />} />
          <Route path="endpoints" element={<Endpoints />} />
          <Route path="users" element={<Users />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="policies" element={<Policies />} />
          <Route path="audit" element={<Audit />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </QueryClientProvider>
  );
}
