import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, type ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { ApiError } from "./api";
import { AuthProvider, useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { I18nProvider, t } from "./i18n";
import { LoginPage } from "./pages/Login";
import { ForcePasswordChange } from "./pages/ForcePasswordChange";

// Pages load on demand: charts (ECharts) and the network map (Cytoscape) never slow down other pages.
const named = <T extends Record<string, unknown>>(loader: () => Promise<T>, key: keyof T) =>
  lazy(async () => ({ default: (await loader())[key] as React.ComponentType }));

const DashboardPage = named(() => import("./pages/Dashboard"), "DashboardPage");
const DiscoveryPage = named(() => import("./pages/Discovery"), "DiscoveryPage");
const AssetsPage = named(() => import("./pages/Assets"), "AssetsPage");
const AssetDetailPage = named(() => import("./pages/AssetDetail"), "AssetDetailPage");
const ServicesPage = named(() => import("./pages/Services"), "ServicesPage");
const AlertsPage = named(() => import("./pages/Alerts"), "AlertsPage");
const EventsPage = named(() => import("./pages/Alerts"), "EventsPage");
const ScansPage = named(() => import("./pages/Scans"), "ScansPage");
const ScanDetailPage = named(() => import("./pages/Scans"), "ScanDetailPage");
const UsersPage = named(() => import("./pages/Admin"), "UsersPage");
const AuditPage = named(() => import("./pages/Admin"), "AuditPage");
const AccountPage = named(() => import("./pages/Admin"), "AccountPage");
const FusionPage = named(() => import("./pages/Fusion"), "FusionPage");
const TopologyPage = named(() => import("./pages/Topology"), "TopologyPage");
const ProfilesPage = named(() => import("./pages/Profiles"), "ProfilesPage");
const VaultPage = named(() => import("./pages/Vault"), "VaultPage");
const SettingsPage = named(() => import("./pages/Settings"), "SettingsPage");
const ReportsPage = named(() => import("./pages/Reports"), "ReportsPage");
const DirectoryPage = named(() => import("./pages/Directory"), "DirectoryPage");
const VulnerabilitiesPage = named(() => import("./pages/Vulnerabilities"), "VulnerabilitiesPage");
const PhysicalPage = named(() => import("./pages/Physical"), "PhysicalPage");
const OperationsPage = named(() => import("./pages/Operations"), "OperationsPage");
const CompliancePage = named(() => import("./pages/Compliance"), "CompliancePage");

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (count, error) => !(error instanceof ApiError && [401, 403, 404].includes(error.status)) && count < 2,
      refetchOnWindowFocus: false,
      staleTime: 5000,
    },
  },
});

function Guard({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth();
  return can(permission) ? <>{children}</> : <p className="text-sm text-slate-600">{t("ليست لديك صلاحية لعرض هذه الصفحة.", "You do not have permission to view this page.")}</p>;
}

function Shell() {
  const { me, loading } = useAuth();
  if (loading) return <Loading />;
  if (!me) return <LoginPage />;
  if (me.user.must_change_password) return <ForcePasswordChange />;
  const g = (permission: string, el: ReactNode) => <Guard permission={permission}>{el}</Guard>;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={g("dashboard:read", <DashboardPage />)} />
        <Route path="topology" element={g("asset:read", <TopologyPage />)} />
        <Route path="fusion" element={g("asset:read", <FusionPage />)} />
        <Route path="reports" element={g("report:read", <ReportsPage />)} />
        <Route path="compliance" element={g("report:read", <CompliancePage />)} />
        <Route path="directory" element={g("directory:read", <DirectoryPage />)} />
        <Route path="vulnerabilities" element={g("asset:read", <VulnerabilitiesPage />)} />
        <Route path="physical" element={g("asset:read", <PhysicalPage />)} />
        <Route path="operations" element={g("data:manage", <OperationsPage />)} />
        <Route path="discovery" element={g("scope:read", <DiscoveryPage />)} />
        <Route path="assets" element={g("asset:read", <AssetsPage />)} />
        <Route path="assets/:id" element={g("asset:read", <AssetDetailPage />)} />
        <Route path="services" element={g("asset:read", <ServicesPage />)} />
        <Route path="alerts" element={g("alert:read", <AlertsPage />)} />
        <Route path="events" element={g("alert:read", <EventsPage />)} />
        <Route path="scans" element={g("scan:read", <ScansPage />)} />
        <Route path="scans/:id" element={g("scan:read", <ScanDetailPage />)} />
        <Route path="profiles" element={g("scan:read", <ProfilesPage />)} />
        <Route path="vault" element={g("remote:verify", <VaultPage />)} />
        <Route path="users" element={g("user:manage", <UsersPage />)} />
        <Route path="audit" element={g("audit:read", <AuditPage />)} />
        <Route path="settings" element={g("data:manage", <SettingsPage />)} />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <BrowserRouter>
            <Shell />
          </BrowserRouter>
        </AuthProvider>
      </QueryClientProvider>
    </I18nProvider>
  );
}
