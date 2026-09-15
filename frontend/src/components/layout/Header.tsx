import React from 'react';
import { Shield, RefreshCw, UploadCloud, Server } from 'lucide-react';
import { HealthResponse } from '../../types/api';
import { SAMPLE_MANIFESTS, SampleManifest } from '../../utils/samples';

interface HeaderProps {
  projectName?: string;
  projectVersion?: string | null;
  health: HealthResponse | null;
  healthLoading: boolean;
  onOpenUpload: () => void;
  onLoadSample: (sample: SampleManifest) => void;
  onReset: () => void;
  isAnalyzing: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  projectName,
  projectVersion,
  health,
  healthLoading,
  onOpenUpload,
  onLoadSample,
  onReset,
  isAnalyzing,
}) => {
  return (
    <header className="app-header">
      <div className="header-left">
        <div className="app-branding" onClick={onReset} role="button" tabIndex={0}>
          <div className="brand-icon-wrapper">
            <Shield size={20} className="brand-icon" />
          </div>
          <div className="brand-text">
            <div className="brand-title">
              RippleGuard <span className="brand-tag">SDG 9</span>
            </div>
            <div className="brand-subtitle">Dependency Risk & Compromise Simulation</div>
          </div>
        </div>

        {projectName && (
          <div className="project-badge-container">
            <span className="project-label">PROJECT:</span>
            <span className="project-name mono">{projectName}</span>
            {projectVersion && <span className="project-ver mono">v{projectVersion}</span>}
          </div>
        )}
      </div>

      <div className="header-right">
        {/* Sample Quick Loader Dropdown */}
        <div className="sample-quick-loader">
          <select
            className="sample-select"
            defaultValue=""
            disabled={isAnalyzing}
            onChange={(e) => {
              const selected = SAMPLE_MANIFESTS.find((s) => s.id === e.target.value);
              if (selected) {
                onLoadSample(selected);
                e.target.value = ''; // Reset select
              }
            }}
          >
            <option value="" disabled>
              Load Demo Manifest...
            </option>
            {SAMPLE_MANIFESTS.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </div>

        {/* Upload Manifest Button */}
        <button
          className="btn-header-primary"
          onClick={onOpenUpload}
          disabled={isAnalyzing}
          title="Upload package.json and package-lock.json"
        >
          <UploadCloud size={15} />
          <span>Upload Manifest</span>
        </button>

        {/* Backend health status badge */}
        <div
          className={`backend-health-badge ${
            health?.status === 'ok' ? 'health-ok' : healthLoading ? 'health-loading' : 'health-down'
          }`}
          title={
            health?.status === 'ok'
              ? `Backend Connected: ${health.app_name} v${health.version} (${health.environment})`
              : 'Backend not reachable on http://127.0.0.1:8000'
          }
        >
          <Server size={13} />
          <span className="health-dot" />
          <span className="health-text">
            {health?.status === 'ok' ? 'API 8000' : healthLoading ? 'Connecting...' : 'API Offline'}
          </span>
        </div>

        {/* Reset button if an analysis is active */}
        {projectName && (
          <button
            className="btn-header-icon"
            onClick={onReset}
            title="Clear and Start New Analysis"
          >
            <RefreshCw size={15} />
          </button>
        )}
      </div>
    </header>
  );
};
