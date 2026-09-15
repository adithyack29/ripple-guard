import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCode,
  FileCheck,
  X,
  AlertCircle,
  Sparkles,
  Info,
  CheckCircle2,
} from 'lucide-react';
import { SAMPLE_MANIFESTS, SampleManifest } from '../../utils/samples';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalyze: (packageJson: File, packageLockJson?: File | null) => Promise<void>;
  onLoadSample: (sample: SampleManifest) => Promise<void>;
  isAnalyzing: boolean;
  error: string | null;
}

export const UploadModal: React.FC<UploadModalProps> = ({
  isOpen,
  onClose,
  onAnalyze,
  onLoadSample,
  isAnalyzing,
  error,
}) => {
  const [packageJsonFile, setPackageJsonFile] = useState<File | null>(null);
  const [packageLockFile, setPackageLockFile] = useState<File | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const [isDraggingPkg, setIsDraggingPkg] = useState(false);
  const [isDraggingLock, setIsDraggingLock] = useState(false);

  const pkgInputRef = useRef<HTMLInputElement>(null);
  const lockInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handlePackageJsonSelect = (file: File) => {
    setLocalError(null);
    if (!file.name.endsWith('.json')) {
      setLocalError('File must be a valid JSON file (e.g. package.json)');
      return;
    }
    setPackageJsonFile(file);
  };

  const handlePackageLockSelect = (file: File) => {
    setLocalError(null);
    if (!file.name.endsWith('.json')) {
      setLocalError('Lockfile must be a valid JSON file (e.g. package-lock.json)');
      return;
    }
    setPackageLockFile(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageJsonFile) {
      setLocalError('Please select or drop a package.json file.');
      return;
    }
    await onAnalyze(packageJsonFile, packageLockFile);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-container">
        <div className="modal-header">
          <div className="modal-title-group">
            <UploadCloud size={20} className="modal-icon" />
            <div>
              <h2 className="modal-title">Analyze NPM Supply Chain</h2>
              <p className="modal-subtitle">
                Upload your project manifests to construct a full dependency graph & evaluate compromise risks.
              </p>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} disabled={isAnalyzing}>
            <X size={18} />
          </button>
        </div>

        {(error || localError) && (
          <div className="modal-error-alert">
            <AlertCircle size={16} />
            <span>{localError || error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="modal-form">
          <div className="upload-slots-grid">
            {/* Slot 1: package.json (Required) */}
            <div
              className={`upload-slot ${packageJsonFile ? 'has-file' : ''} ${
                isDraggingPkg ? 'is-dragging' : ''
              }`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDraggingPkg(true);
              }}
              onDragLeave={() => setIsDraggingPkg(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingPkg(false);
                if (e.dataTransfer.files?.[0]) {
                  handlePackageJsonSelect(e.dataTransfer.files[0]);
                }
              }}
              onClick={() => pkgInputRef.current?.click()}
            >
              <input
                ref={pkgInputRef}
                type="file"
                accept=".json"
                style={{ display: 'none' }}
                onChange={(e) => {
                  if (e.target.files?.[0]) {
                    handlePackageJsonSelect(e.target.files[0]);
                  }
                }}
              />
              <div className="slot-badge required">REQUIRED</div>
              <FileCode size={28} className="slot-icon" />
              <div className="slot-title">package.json</div>
              <div className="slot-desc">
                {packageJsonFile ? (
                  <div className="slot-selected-name mono">
                    <CheckCircle2 size={13} className="text-emerald" /> {packageJsonFile.name} (
                    {(packageJsonFile.size / 1024).toFixed(1)} KB)
                  </div>
                ) : (
                  'Click or drag & drop project package.json'
                )}
              </div>
            </div>

            {/* Slot 2: package-lock.json (Optional) */}
            <div
              className={`upload-slot ${packageLockFile ? 'has-file' : ''} ${
                isDraggingLock ? 'is-dragging' : ''
              }`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDraggingLock(true);
              }}
              onDragLeave={() => setIsDraggingLock(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingLock(false);
                if (e.dataTransfer.files?.[0]) {
                  handlePackageLockSelect(e.dataTransfer.files[0]);
                }
              }}
              onClick={() => lockInputRef.current?.click()}
            >
              <input
                ref={lockInputRef}
                type="file"
                accept=".json"
                style={{ display: 'none' }}
                onChange={(e) => {
                  if (e.target.files?.[0]) {
                    handlePackageLockSelect(e.target.files[0]);
                  }
                }}
              />
              <div className="slot-badge optional">OPTIONAL</div>
              <FileCheck size={28} className="slot-icon" />
              <div className="slot-title">package-lock.json</div>
              <div className="slot-desc">
                {packageLockFile ? (
                  <div className="slot-selected-name mono">
                    <CheckCircle2 size={13} className="text-emerald" /> {packageLockFile.name} (
                    {(packageLockFile.size / 1024).toFixed(1)} KB)
                  </div>
                ) : (
                  'Click or drag & drop lockfile (v2/v3)'
                )}
              </div>
            </div>
          </div>

          {/* Mode explanation banner */}
          <div className="upload-info-box">
            <Info size={15} />
            <div>
              {packageLockFile ? (
                <span>
                  <strong>Full Graph Mode:</strong> Package lockfile allows resolving exact versions, transitive dependency chains, and accurate compromise propagation.
                </span>
              ) : (
                <span>
                  <strong>Direct Dependencies Only:</strong> Without package-lock.json, transitive dependencies cannot be resolved. Compromise simulation requires resolved versions.
                </span>
              )}
            </div>
          </div>

          <div className="modal-actions-row">
            <button
              type="submit"
              className="btn-submit-analyze"
              disabled={!packageJsonFile || isAnalyzing}
            >
              {isAnalyzing ? (
                <>
                  <span className="spinner-inline" /> Running Analysis & OSV Lookup...
                </>
              ) : (
                'Analyze Dependencies'
              )}
            </button>
          </div>
        </form>

        {/* Quick Demo Fixtures section */}
        <div className="modal-samples-section">
          <div className="samples-header">
            <Sparkles size={14} className="text-cyan" />
            <span>Or analyze with a live demo fixture:</span>
          </div>

          <div className="samples-list">
            {SAMPLE_MANIFESTS.map((sample) => (
              <button
                key={sample.id}
                className="sample-card-btn"
                disabled={isAnalyzing}
                onClick={() => onLoadSample(sample)}
              >
                <div className="sample-card-name">{sample.name}</div>
                <div className="sample-card-desc">{sample.description}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
