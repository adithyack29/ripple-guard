import React from 'react';
import { Search, Filter, ShieldAlert, Layers, Maximize2, RotateCcw } from 'lucide-react';
import { useReactFlow } from '@xyflow/react';

interface GraphToolbarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  relationFilter: 'all' | 'direct' | 'transitive';
  onRelationFilterChange: (val: 'all' | 'direct' | 'transitive') => void;
  vulnerableOnly: boolean;
  onVulnerableOnlyChange: (val: boolean) => void;
  totalNodes: number;
  matchedCount: number;
}

export const GraphToolbar: React.FC<GraphToolbarProps> = ({
  searchQuery,
  onSearchChange,
  relationFilter,
  onRelationFilterChange,
  vulnerableOnly,
  onVulnerableOnlyChange,
  totalNodes,
  matchedCount,
}) => {
  const { fitView } = useReactFlow();

  return (
    <div className="graph-sidebar-toolbar">
      {/* Search Input */}
      <div className="toolbar-search-box">
        <Search size={14} className="search-icon" />
        <input
          type="text"
          className="search-input mono"
          placeholder="Filter package name..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
        />
        {searchQuery && (
          <button className="search-clear-btn" onClick={() => onSearchChange('')}>
            ×
          </button>
        )}
      </div>

      {searchQuery && (
        <div className="search-match-text">
          Showing {matchedCount} of {totalNodes} packages
        </div>
      )}

      {/* Filter Section */}
      <div className="toolbar-section">
        <div className="toolbar-section-title">
          <Filter size={12} /> Filter Graph
        </div>

        <div className="filter-group">
          <label className="filter-label">Relation</label>
          <div className="filter-pills">
            <button
              className={`pill-btn ${relationFilter === 'all' ? 'is-active' : ''}`}
              onClick={() => onRelationFilterChange('all')}
            >
              All
            </button>
            <button
              className={`pill-btn ${relationFilter === 'direct' ? 'is-active' : ''}`}
              onClick={() => onRelationFilterChange('direct')}
            >
              Direct
            </button>
            <button
              className={`pill-btn ${relationFilter === 'transitive' ? 'is-active' : ''}`}
              onClick={() => onRelationFilterChange('transitive')}
            >
              Transitive
            </button>
          </div>
        </div>

        <div className="filter-toggle-row">
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={vulnerableOnly}
              onChange={(e) => onVulnerableOnlyChange(e.target.checked)}
            />
            <ShieldAlert size={13} className="text-amber" />
            <span>Vulnerable only</span>
          </label>
        </div>
      </div>

      {/* Quick Viewport Controls */}
      <div className="toolbar-section">
        <div className="toolbar-section-title">
          <Layers size={12} /> Viewport
        </div>
        <div className="viewport-buttons">
          <button
            className="btn-toolbar-action"
            onClick={() => fitView({ padding: 0.15, duration: 400 })}
            title="Fit graph to view"
          >
            <Maximize2 size={13} /> Fit View
          </button>
          <button
            className="btn-toolbar-action"
            onClick={() => fitView({ duration: 400 })}
            title="Reset position"
          >
            <RotateCcw size={13} /> Reset
          </button>
        </div>
      </div>

      {/* Graph Legend */}
      <div className="toolbar-section legend-section">
        <div className="toolbar-section-title">Legend</div>
        <div className="legend-items">
          <div className="legend-item">
            <span className="legend-dot dot-root" />
            <span>Application Root</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot dot-direct" />
            <span>Direct Dependency</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot dot-transitive" />
            <span>Transitive Dependency</span>
          </div>
          <div className="legend-divider" />
          <div className="legend-item">
            <span className="legend-dot dot-compromised" />
            <span>Compromised Target</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot dot-affected" />
            <span>Affected Dependent</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot dot-app-impact" />
            <span>Application Root Breached</span>
          </div>
        </div>
      </div>
    </div>
  );
};
