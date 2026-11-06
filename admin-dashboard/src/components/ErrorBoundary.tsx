import React, { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("FraudShield Dashboard Component Error:", error, errorInfo);
  }

  private handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="bg-slate-900 border border-red-500/30 rounded-xl p-6 text-center my-4 shadow-xl">
          <div className="inline-flex p-3 bg-red-500/10 rounded-full text-red-400 mb-3">
            <AlertTriangle className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-white mb-2">
            {this.props.fallbackTitle || "Component Encountered an Error"}
          </h3>
          <p className="text-sm text-slate-400 mb-4 max-w-md mx-auto">
            {this.state.error?.message || "An unexpected rendering error occurred. The rest of the dashboard remains operational."}
          </p>
          <button
            onClick={this.handleRetry}
            className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-lg transition-colors shadow-md"
          >
            <RefreshCw className="w-4 h-4" />
            Retry Component
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

