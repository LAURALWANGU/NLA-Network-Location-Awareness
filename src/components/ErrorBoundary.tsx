import React from 'react';
import { ShieldAlert, RotateCcw } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  errorMessage: string;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: error.message || 'An unexpected runtime error occurred.',
    };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#050B16] text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-[#0B1426] border border-rose-500/30 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-3 text-rose-400">
              <ShieldAlert className="w-6 h-6 shrink-0" />
              <h1 className="text-lg font-semibold text-slate-100">
                NLA Runtime Protection Triggered
              </h1>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              The interface encountered an unexpected state or database permission error.
            </p>
            <pre className="text-xs font-mono bg-[#050B16] border border-slate-800 rounded-lg p-3 overflow-x-auto text-rose-300 whitespace-pre-wrap break-all">
              {this.state.errorMessage}
            </pre>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium bg-sky-600 hover:bg-sky-500 text-white rounded-lg transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Reload NLA Console
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
