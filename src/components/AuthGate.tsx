import React from 'react';
import { Shield, Lock, Globe, FileText } from 'lucide-react';
import { useNla } from '../context/NlaContext';

export function AuthGate() {
  const { signInWithGoogle, signingIn, authError } = useNla();

  return (
    <div className="min-h-screen bg-[#050B16] text-slate-100 flex flex-col justify-between p-6 lg:p-10">
      <header className="max-w-6xl w-full mx-auto flex items-center justify-between gap-8 border-b border-slate-800/80 pb-4">
        <span className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 font-display">
          NLA
        </span>
        <span className="text-xs text-slate-400 hidden sm:inline">
          Newtonix Tech House
        </span>
        <button
          type="button"
          onClick={() => void signInWithGoogle()}
          disabled={signingIn}
          className="px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
        >
          {signingIn ? 'Signing In...' : 'Sign In with Google'}
        </button>
      </header>

      <main className="max-w-5xl w-full mx-auto my-auto py-12 grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
        <div className="lg:col-span-7 space-y-6">
          <div className="space-y-3">
            <p className="text-xs font-semibold text-sky-400 tracking-wide">
              Newtonix Tech House · Digital Privacy Intelligence
            </p>
            <h1 className="text-3xl sm:text-4xl font-bold text-slate-100 leading-tight font-display">
              Network &amp; Location Awareness
            </h1>
            <p className="text-sm font-semibold text-sky-300 tracking-wide">
              SEE YOUR DATA. KNOW ITS DESTINATION. CONTROL YOUR DIGITAL PRIVACY.
            </p>
            <p className="text-sm text-slate-300 leading-relaxed max-w-xl">
              Reveal what personal information applications request, which third-party organizations receive network transmissions, where traffic routes globally, and what complex privacy agreements actually disclose.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void signInWithGoogle()}
              disabled={signingIn}
              className="inline-flex items-center gap-2.5 px-6 py-3 text-sm font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              <Shield className="w-4 h-4" />
              {signingIn ? 'Authenticating Workspace...' : 'Enter NLA Workspace'}
            </button>
          </div>

          {authError && (
            <div className="p-3 bg-rose-950/50 border border-rose-500/40 rounded-lg text-xs text-rose-200 max-w-lg">
              {authError}
            </div>
          )}
        </div>

        <div className="lg:col-span-5 space-y-3">
          <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 flex items-start gap-3">
            <Globe className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Global Destination Topology
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Inspect live DNS, TLS certificate subjects, IP geolocation, and ASN operators with explicit evidence confidence.
              </p>
            </div>
          </div>
          <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 flex items-start gap-3">
            <FileText className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Privacy Agreement Intelligence
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Analyze policy URLs, uploaded PDFs, and version diffs into clear 8-point clause breakdowns.
              </p>
            </div>
          </div>
          <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 flex items-start gap-3">
            <Lock className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Zero-Trust Isolated Storage
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Authenticated Firestore persistence, SHA-256 forensic exports, and immutable audit logs.
              </p>
            </div>
          </div>
        </div>
      </main>

      <footer className="max-w-6xl w-full mx-auto border-t border-slate-800/80 pt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
        <span>NLA — Network &amp; Location Awareness</span>
        <span>© {new Date().getFullYear()} Newtonix Tech House. User-authorized inspection only.</span>
      </footer>
    </div>
  );
}
