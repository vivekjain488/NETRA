import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router-dom";
import { hasAccessToken } from "@/lib/api";
import { AppShell } from "@/components/layout/AppShell";
import { SignInGate } from "@/components/layout/SignInGate";
import { Overview } from "@/pages/Overview";
import { Endpoints } from "@/pages/Endpoints";
import { Sessions } from "@/pages/Sessions";
import { Events } from "@/pages/Events";
import { Incidents } from "@/pages/Incidents";
import { Policies } from "@/pages/Policies";
import { Audit } from "@/pages/Audit";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A stale risk figure is misleading in an operations console, so cached
      // values are never served as fresh.
      staleTime: 0,
      refetchOnWindowFocus: true,
      retry: false,
    },
  },
});

function Console() {
  const [signedIn, setSignedIn] = useState(hasAccessToken());

  if (!signedIn) {
    return <SignInGate onSignedIn={() => setSignedIn(true)} />;
  }

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Overview />} />
        <Route path="endpoints" element={<Endpoints />} />
        <Route path="sessions" element={<Sessions />} />
        <Route path="events" element={<Events />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="policies" element={<Policies />} />
        <Route path="audit" element={<Audit />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Console />
    </QueryClientProvider>
  );
}
