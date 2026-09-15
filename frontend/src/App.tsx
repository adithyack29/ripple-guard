import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { apiClient, ApiError } from './api/client';
import {
  AnalyzeResponse,
  HealthResponse,
  SimulateResponse,
  DependencyNode,
} from './types/api';
import { Header } from './components/layout/Header';
import { SummaryBar } from './components/layout/SummaryBar';
import { GraphToolbar } from './components/panels/GraphToolbar';
import { DependencyGraphContent } from './components/graph/DependencyGraph';
import { NodeDetailPanel } from './components/panels/NodeDetailPanel';
import { PriorityTable } from './components/panels/PriorityTable';
import { UploadModal } from './components/upload/UploadModal';
import { SAMPLE_MANIFESTS, SampleManifest } from './utils/samples';
import { Shield, UploadCloud, Sparkles, AlertCircle } from 'lucide-react';

import './styles/index.css';
import './styles/components.css';

export const App: React.FC = () => {
  // Backend status
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);

  // Analysis State
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Active Simulation State
  const [simulation, setSimulation] = useState<SimulateResponse | null>(null);
  const [simulationPhase, setSimulationPhase] = useState<'idle' | 'simulating' | 'complete'>('idle');
  const simTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationError, setSimulationError] = useState<string | null>(null);

  // Selection & UI State
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);

  // Clear timer on unmount
  useEffect(() => {
    return () => {
      if (simTimerRef.current) clearTimeout(simTimerRef.current);
    };
  }, []);

  // Graph Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [relationFilter, setRelationFilter] = useState<'all' | 'direct' | 'transitive'>('all');
  const [vulnerableOnly, setVulnerableOnly] = useState(false);

  // Initial Health Check
  const checkHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      const h = await apiClient.checkHealth();
      setHealth(h);
    } catch {
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  // Run Analysis on File/Blob inputs
  const handleAnalyzeFiles = async (
    packageJson: File | Blob,
    packageLockJson?: File | Blob | null
  ) => {
    if (simTimerRef.current) clearTimeout(simTimerRef.current);
    setIsAnalyzing(true);
    setAnalysisError(null);
    setSimulation(null);
    setSimulationPhase('idle');

    try {
      const res = await apiClient.analyze(packageJson, packageLockJson);
      setAnalysis(res);
      setIsUploadOpen(false);

      // Default select the root node or highest risk node
      const rootNode = res.nodes.find((n) => n.relation === 'root');
      setSelectedNodeId(rootNode ? rootNode.id : res.nodes[0]?.id || null);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setAnalysisError(err.message);
      } else {
        setAnalysisError('An unexpected error occurred while analyzing dependencies.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Load Real Sample Manifest via HTTP multipart
  const handleLoadSample = async (sample: SampleManifest) => {
    const pkgBlob = new Blob([sample.packageJson], { type: 'application/json' });
    const lockBlob = sample.packageLockJson
      ? new Blob([sample.packageLockJson], { type: 'application/json' })
      : null;

    const pkgFile = new File([pkgBlob], 'package.json', { type: 'application/json' });
    const lockFile = lockBlob
      ? new File([lockBlob], 'package-lock.json', { type: 'application/json' })
      : null;

    await handleAnalyzeFiles(pkgFile, lockFile);
  };

  // Run Compromise Simulation
  const handleSimulate = async (nodeId: string) => {
    if (!analysis) return;

    setIsSimulating(true);
    setSimulationError(null);

    try {
      const res = await apiClient.simulate(analysis.analysis_id, nodeId);
      setSimulation(res);
      setSelectedNodeId(nodeId);
      setSimulationPhase('simulating');

      // Sequence finite animation window, then transition to 'complete'
      // Single-hop: ~2.5s visible motion -> 2650ms transition
      // Multi-hop: ~1.75s per hop -> (maxHops * 1750 + 150)ms transition
      if (simTimerRef.current) clearTimeout(simTimerRef.current);
      const maxHops = res.blast_radius.max_propagation_depth || 1;
      const durationMs = maxHops <= 1 ? 2650 : Math.round(maxHops * 1750 + 150);
      simTimerRef.current = setTimeout(() => {
        setSimulationPhase('complete');
      }, durationMs);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.isAnalysisExpired) {
          setSimulationError('Analysis expired from backend memory. Please re-analyze the project manifest.');
        } else {
          setSimulationError(err.message);
        }
      } else {
        setSimulationError('Failed to simulate compromise propagation.');
      }
    } finally {
      setIsSimulating(false);
    }
  };

  // Clear Simulation (Exit Simulation)
  const handleClearSimulation = () => {
    if (simTimerRef.current) clearTimeout(simTimerRef.current);
    setSimulation(null);
    setSimulationPhase('idle');
    setSimulationError(null);
  };

  // Reset entire dashboard
  const handleReset = () => {
    if (simTimerRef.current) clearTimeout(simTimerRef.current);
    setAnalysis(null);
    setSimulation(null);
    setSimulationPhase('idle');
    setSelectedNodeId(null);
    setAnalysisError(null);
    setSimulationError(null);
    setSearchQuery('');
  };

  // Filter nodes according to search and filters
  const filteredNodes = useMemo(() => {
    if (!analysis) return [];

    return analysis.nodes.filter((node) => {
      // Search filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesName = node.name.toLowerCase().includes(q);
        const matchesId = node.id.toLowerCase().includes(q);
        if (!matchesName && !matchesId) return false;
      }

      // Relation filter
      if (relationFilter !== 'all' && node.relation !== 'root') {
        if (node.relation !== relationFilter) return false;
      }

      // Vulnerable only filter
      if (vulnerableOnly && node.relation !== 'root') {
        if (node.vulnerabilities.length === 0) return false;
      }

      return true;
    });
  }, [analysis, searchQuery, relationFilter, vulnerableOnly]);

  // Edges matching filtered nodes
  const filteredEdges = useMemo(() => {
    if (!analysis) return [];
    const validNodeIds = new Set(filteredNodes.map((n) => n.id));
    return analysis.edges.filter(
      (e) => validNodeIds.has(e.source) && validNodeIds.has(e.target)
    );
  }, [analysis, filteredNodes]);

  // Selected Node Data
  const selectedNode: DependencyNode | null = useMemo(() => {
    if (!analysis || !selectedNodeId) return null;
    return analysis.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [analysis, selectedNodeId]);

  return (
    <div className="app-shell">
      {/* Top Header */}
      <Header
        projectName={analysis?.project.name}
        projectVersion={analysis?.project.version}
        health={health}
        healthLoading={healthLoading}
        onOpenUpload={() => setIsUploadOpen(true)}
        onLoadSample={handleLoadSample}
        onReset={handleReset}
        isAnalyzing={isAnalyzing}
      />

      {/* Global Error Banner */}
      {(analysisError || simulationError) && (
        <div className="modal-error-alert">
          <AlertCircle size={16} />
          <span>{analysisError || simulationError}</span>
          <button
            className="search-clear-btn"
            onClick={() => {
              setAnalysisError(null);
              setSimulationError(null);
            }}
            style={{ marginLeft: 'auto' }}
          >
            ×
          </button>
        </div>
      )}

      {/* Main Analysis View or Welcome View */}
      {analysis ? (
        <>
          {/* Summary Metric Strip */}
          <SummaryBar
            analysis={analysis}
            simulation={simulation}
            simulationPhase={simulationPhase}
            onClearSimulation={handleClearSimulation}
          />

          {/* Central Workspace */}
          <div className="main-workspace">
            <ReactFlowProvider>
              {/* Left Toolbar */}
              <GraphToolbar
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
                relationFilter={relationFilter}
                onRelationFilterChange={setRelationFilter}
                vulnerableOnly={vulnerableOnly}
                onVulnerableOnlyChange={setVulnerableOnly}
                totalNodes={analysis.nodes.length}
                matchedCount={filteredNodes.length}
              />

              {/* Center Interactive Graph */}
              <DependencyGraphContent
                nodes={filteredNodes}
                edges={filteredEdges}
                selectedNodeId={selectedNodeId}
                simulation={simulation}
                isAnimatingSimulation={simulationPhase === 'simulating'}
                onSelectNode={(id) => setSelectedNodeId(id)}
              />
            </ReactFlowProvider>

            {/* Right Node Detail & Simulation Panel */}
            <NodeDetailPanel
              node={selectedNode}
              simulation={simulation}
              simulationPhase={simulationPhase}
              isSimulating={isSimulating}
              onSimulate={handleSimulate}
              onClearSimulation={handleClearSimulation}
              onSelectNode={(id) => setSelectedNodeId(id)}
            />
          </div>

          {/* Bottom Mitigation Priority Drawer */}
          <PriorityTable
            priorities={analysis.mitigation_priorities}
            selectedNodeId={selectedNodeId}
            onSelectNode={(id) => setSelectedNodeId(id)}
          />
        </>
      ) : (
        /* Welcome / Empty Screen */
        <div className="welcome-screen">
          <div className="welcome-card">
            <div className="welcome-icon-box">
              <Shield size={28} />
            </div>

            <h1 className="welcome-title">RippleGuard Analysis Console</h1>

            <p className="welcome-desc">
              Traditional scanners ask <em>"Is this package vulnerable?"</em> RippleGuard models
              your entire dependency hierarchy and asks <em>"What happens if this package is compromised?"</em>
            </p>

            <div className="welcome-actions">
              <button
                className="btn-welcome-primary"
                onClick={() => setIsUploadOpen(true)}
              >
                <UploadCloud size={16} /> Upload Manifest
              </button>

              <button
                className="btn-welcome-secondary"
                onClick={() => handleLoadSample(SAMPLE_MANIFESTS[0])}
                disabled={isAnalyzing}
              >
                <Sparkles size={16} className="text-cyan" /> Try Live Demo Manifest
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manifest Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onAnalyze={(pkg, lock) => handleAnalyzeFiles(pkg, lock)}
        onLoadSample={handleLoadSample}
        isAnalyzing={isAnalyzing}
        error={analysisError}
      />
    </div>
  );
};
