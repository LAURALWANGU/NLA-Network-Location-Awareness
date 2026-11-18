import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  AppWindow,
  Bell,
  BookOpen,
  Bot,
  Building2,
  FileCheck2,
  FileText,
  Fingerprint,
  Globe,
  Info,
  LayoutDashboard,
  LogOut,
  Menu,
  MonitorSmartphone,
  Network,
  Settings,
  Shield,
  X,
} from 'lucide-react';
import { useNla } from './context/NlaContext';
import { AuthGate } from './components/AuthGate';
import { OverviewDashboard } from './components/OverviewDashboard';
import { GlobalDataMap } from './components/GlobalDataMap';
import { ApplicationScanner } from './components/ApplicationScanner';
import {
  DataCollectionIntelligence,
  ThirdPartyTrackerIntelligence,
} from './components/CollectionAndTrackers';
import { PrivacyAgreementAnalyzer } from './components/PrivacyAgreementAnalyzer';
import {
  LiveNetworkMonitor,
  PrivacyRiskAnalytics,
} from './components/LiveMonitorAndRisks';
import {
  DigitalForensics,
  ReportsAndEvidence,
} from './components/ForensicsAndReports';
import { AiAssistantView } from './components/AiAssistantView';
import {
  AboutNewtonixView,
  DeviceManagement,
  SettingsView,
} from './components/DevicesSettingsAbout';
import { OnboardingFlow } from './components/OnboardingFlow';
import type { NavSectionId } from './types/nla';

const NAV_ITEMS: Array<{
  id: NavSectionId;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'overview', label: 'Overview Dashboard', icon: LayoutDashboard },
  { id: 'map', label: 'Global Data Map', icon: Globe },
  { id: 'apps', label: 'Application Scanner', icon: AppWindow },
  { id: 'collection', label: 'Data Collection Intelligence', icon: Network },
  { id: 'third-parties', label: 'Third-Party Tracker Intelligence', icon: Building2 },
  { id: 'policies', label: 'Privacy Agreement Analyzer', icon: FileText },
  { id: 'live-monitor', label: 'Live Network Monitor', icon: Activity },
  { id: 'risks', label: 'Privacy Risk Analytics', icon: AlertTriangle },
  { id: 'forensics', label: 'Digital Forensics', icon: Fingerprint },
  { id: 'reports', label: 'Reports and Evidence', icon: FileCheck2 },
  { id: 'assistant', label: 'AI Intelligence Assistant', icon: Bot },
  { id: 'devices', label: 'Device Management', icon: MonitorSmartphone },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'about', label: 'About Newtonix Tech House', icon: Info },
];

export default function App() {
  const {
    user,
    profile,
    authReady,
    logout,
    riskAlerts,
    setAlertStatus,
    liveAlertBanners,
    dismissAlertBanner,
    openOnboarding,
  } = useNla();
  const [activeTab, setActiveTab] = useState<NavSectionId>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [alertMenuOpen, setAlertMenuOpen] = useState(false);

  if (!authReady) {
    return (
      <div className="min-h-screen bg-[#050B16] text-slate-300 flex items-center justify-center text-sm font-mono">
        Initializing NLA Workspace...
      </div>
    );
  }

  if (!user) {
    return <AuthGate />;
  }

  const activeNav = NAV_ITEMS.find((item) => item.id === activeTab) || NAV_ITEMS[0];
  const openRiskCount = riskAlerts.filter((a) => a.status === 'open').length;

  const handleSelectNav = (id: NavSectionId) => {
    setActiveTab(id);
    setMobileMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#050B16] text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:fixed lg:inset-y-0 bg-[#070E1C] border-r border-slate-800/90">
        <div className="px-5 py-4 border-b border-slate-800/80 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/40 flex items-center justify-center text-sky-400 shrink-0">
            <Shield className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="text-base font-bold text-slate-100 font-display leading-tight">
              NLA
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              Newtonix Tech House
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="NLA Primary Navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleSelectNav(item.id)}
                className={`w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                  active
                    ? 'bg-sky-600/20 text-sky-300 border border-sky-500/30'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <Icon className="w-4 h-4 shrink-0" />
                  <span className="truncate">{item.label}</span>
                </span>
                {item.id === 'risks' && openRiskCount > 0 && (
                  <span className="font-mono tabular-nums text-[11px] text-amber-400 shrink-0">
                    {openRiskCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/80 flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-200 truncate">
              {profile?.displayName || user.displayName || 'Analyst'}
            </div>
            <div className="text-[11px] text-slate-500 truncate">{user.email}</div>
          </div>
          <button
            type="button"
            onClick={() => void logout()}
            aria-label="Sign out"
            className="p-2 text-slate-400 hover:text-rose-400 rounded-lg hover:bg-slate-800/60 transition-colors shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative w-72 max-w-full bg-[#070E1C] border-r border-slate-800 flex flex-col z-10">
            <div className="px-4 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-100 font-display">NLA · Newtonix</span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation menu"
                className="p-1.5 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => handleSelectNav(item.id)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-xs font-medium text-left ${
                      activeTab === item.id
                        ? 'bg-sky-600/20 text-sky-300'
                        : 'text-slate-300 hover:bg-slate-800/50'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Viewport */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        <header className="sticky top-0 z-30 bg-[#050B16]/95 backdrop-blur border-b border-slate-800/80 px-4 sm:px-6 py-3.5 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-2 text-slate-300 hover:text-white rounded-lg border border-slate-800"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-xs text-slate-400 min-w-0">
              <span className="hidden sm:inline whitespace-nowrap">NLA Workspace</span>
              <span className="hidden sm:inline" aria-hidden="true">/</span>
              <h1 className="text-sm sm:text-base font-semibold text-slate-100 truncate">
                {activeNav.label}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={openOnboarding}
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-[#0B1426] border border-slate-800 hover:border-sky-500 text-slate-200 rounded-lg transition-colors whitespace-nowrap"
            >
              <BookOpen className="w-3.5 h-3.5 text-sky-400" />
              Setup Guide
            </button>

            <div className="relative">
              <button
                type="button"
                onClick={() => setAlertMenuOpen((v) => !v)}
                aria-label="Open real-time alerts center"
                className="relative inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-[#0B1426] border border-slate-800 hover:border-amber-500/60 text-slate-200 rounded-lg transition-colors"
              >
                <Bell className={`w-3.5 h-3.5 ${openRiskCount > 0 ? 'text-amber-400' : 'text-slate-400'}`} />
                <span className="font-mono tabular-nums">{openRiskCount}</span>
              </button>

              {alertMenuOpen && (
                <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-[#070E1C] border border-slate-700 rounded-xl shadow-2xl z-40 overflow-hidden">
                  <div className="px-4 py-3 bg-[#0B1426] border-b border-slate-800 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-100">
                      Real-Time Privacy Alerts ({openRiskCount} open)
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setAlertMenuOpen(false);
                        handleSelectNav('risks');
                      }}
                      className="text-[11px] text-sky-400 hover:underline"
                    >
                      Rules &amp; All Risks
                    </button>
                  </div>
                  <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/80">
                    {riskAlerts.length === 0 ? (
                      <div className="p-5 text-xs text-slate-400 text-center">
                        No privacy alerts fired yet. Real-time alerts appear here when thresholds or external threat feeds trigger.
                      </div>
                    ) : (
                      riskAlerts.slice(0, 8).map((alert) => (
                        <div key={alert.id} className="p-3.5 text-xs space-y-1.5">
                          <div className="flex items-center justify-between gap-2">
                            <span
                              className={`font-semibold uppercase text-[11px] ${
                                alert.severity === 'critical' || alert.severity === 'high'
                                  ? 'text-rose-400'
                                  : 'text-amber-400'
                              }`}
                            >
                              {alert.severity} · {alert.category.replace(/-/g, ' ')}
                            </span>
                            <span className="text-[11px] text-slate-400 capitalize">
                              {alert.status}
                            </span>
                          </div>
                          <div className="font-medium text-slate-100">{alert.title}</div>
                          <div className="text-[11px] text-slate-400">
                            {alert.appName}
                            {alert.externalFeedSource
                              ? ` · External Feed: ${alert.externalFeedSource}`
                              : ''}
                          </div>
                          {alert.status === 'open' && (
                            <button
                              type="button"
                              onClick={() => void setAlertStatus(alert.id, 'acknowledged')}
                              className="text-[11px] text-sky-400 hover:text-sky-300"
                            >
                              Acknowledge
                            </button>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => handleSelectNav('assistant')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <Bot className="w-3.5 h-3.5" />
              NLA Intelligence
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 max-w-[1440px] w-full mx-auto">
          {activeTab === 'overview' && <OverviewDashboard onNavigate={handleSelectNav} />}
          {activeTab === 'map' && <GlobalDataMap />}
          {activeTab === 'apps' && <ApplicationScanner />}
          {activeTab === 'collection' && <DataCollectionIntelligence />}
          {activeTab === 'third-parties' && <ThirdPartyTrackerIntelligence />}
          {activeTab === 'policies' && <PrivacyAgreementAnalyzer />}
          {activeTab === 'live-monitor' && <LiveNetworkMonitor />}
          {activeTab === 'risks' && <PrivacyRiskAnalytics />}
          {activeTab === 'forensics' && <DigitalForensics />}
          {activeTab === 'reports' && <ReportsAndEvidence />}
          {activeTab === 'assistant' && <AiAssistantView />}
          {activeTab === 'devices' && <DeviceManagement />}
          {activeTab === 'settings' && <SettingsView />}
          {activeTab === 'about' && <AboutNewtonixView />}
        </main>

        <footer className="border-t border-slate-800/80 px-6 py-4 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-2">
          <span>NLA — Network &amp; Location Awareness · Newtonix Tech House</span>
          <span>See Your Data. Know Its Destination. Control Your Digital Privacy.</span>
        </footer>
      </div>

      {/* Real-Time Non-Blocking Alert Banner Stack */}
      {liveAlertBanners.length > 0 && (
        <div
          className="fixed bottom-4 right-4 z-40 w-80 sm:w-96 space-y-2.5"
          aria-live="polite"
        >
          {liveAlertBanners.map((banner) => (
            <div
              key={banner.id}
              className="bg-[#0B1426] border border-slate-700 rounded-xl p-4 shadow-2xl space-y-2 text-xs"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <AlertTriangle
                    className={`w-4 h-4 shrink-0 ${
                      banner.severity === 'critical' || banner.severity === 'high'
                        ? 'text-rose-400'
                        : 'text-amber-400'
                    }`}
                  />
                  <span className="font-semibold uppercase text-slate-200">
                    {banner.severity} Privacy Alert
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => dismissAlertBanner(banner.id)}
                  aria-label="Dismiss alert notification"
                  className="text-slate-400 hover:text-slate-100"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="font-medium text-slate-100">{banner.title}</div>
              <div className="text-[11px] text-slate-400">
                {banner.appName}
                {banner.domain ? ` · ${banner.domain}` : ''}
                {banner.externalFeedSource
                  ? ` · External Feed: ${banner.externalFeedSource}`
                  : ''}
              </div>
              <div className="flex items-center gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    dismissAlertBanner(banner.id);
                    handleSelectNav('risks');
                  }}
                  className="text-sky-400 hover:underline font-medium"
                >
                  Inspect Risk &amp; Rules
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Guided User Onboarding Modal */}
      <OnboardingFlow onNavigate={handleSelectNav} />
    </div>
  );
}
