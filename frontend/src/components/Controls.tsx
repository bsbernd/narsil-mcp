import type { ViewType } from '../types/graph';
import type { LayoutType } from './GraphCanvas';

export type DirectionType = 'callers' | 'callees' | 'both';

export interface ControlsProps {
  // Repository selection
  repos: string[];
  selectedRepo: string;
  onRepoChange: (repo: string) => void;

  // View selection
  view: ViewType;
  onViewChange: (view: ViewType) => void;

  // Depth control
  depth: number;
  onDepthChange: (depth: number) => void;

  // Root node filter
  root?: string;
  onRootChange: (root: string | undefined) => void;

  // Direction control (for call graphs)
  direction: DirectionType;
  onDirectionChange: (direction: DirectionType) => void;

  // Max nodes limit
  maxNodes: number;
  onMaxNodesChange: (maxNodes: number) => void;

  // Toggle options
  showMetrics: boolean;
  onShowMetricsChange: (show: boolean) => void;

  clustered: boolean;
  onClusteredChange: (clustered: boolean) => void;

  // Layout
  layout: LayoutType;
  onLayoutChange: (layout: LayoutType) => void;

  // Loading state
  loading?: boolean;
  onRefresh?: () => void;
}

export function Controls({
  repos,
  selectedRepo,
  onRepoChange,
  view,
  onViewChange,
  depth,
  onDepthChange,
  root,
  onRootChange,
  direction,
  onDirectionChange,
  maxNodes,
  onMaxNodesChange,
  showMetrics,
  onShowMetricsChange,
  clustered,
  onClusteredChange,
  layout,
  onLayoutChange,
  loading,
  onRefresh,
}: ControlsProps) {
  return (
    <div className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-5 py-3">
      <div className="flex flex-wrap gap-x-6 gap-y-3 items-center">
        {/* Repository selector */}
        <ControlGroup label="Repository">
          <select
            value={selectedRepo}
            onChange={(e) => onRepoChange(e.target.value)}
            className="w-44 h-8 pl-3 pr-8 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Select...</option>
            {repos.map((repo) => (
              <option key={repo} value={repo}>
                {repo}
              </option>
            ))}
          </select>
        </ControlGroup>

        {/* Divider */}
        <div className="h-6 w-px bg-slate-200 dark:bg-slate-700 hidden sm:block" />

        {/* View type selector */}
        <ControlGroup label="View">
          <select
            value={view}
            onChange={(e) => onViewChange(e.target.value as ViewType)}
            className="w-28 h-8 pl-3 pr-8 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="call">Call Graph</option>
            <option value="import">Imports</option>
            <option value="symbol">Symbol</option>
            <option value="hybrid">Hybrid</option>
            <option value="flow">Flow</option>
          </select>
        </ControlGroup>

        {/* Depth slider */}
        <ControlGroup label={`Depth: ${depth}`}>
          <input
            type="range"
            min="1"
            max="10"
            value={depth}
            onChange={(e) => onDepthChange(parseInt(e.target.value, 10))}
            className="w-20 h-1"
          />
        </ControlGroup>

        {/* Root node filter */}
        <ControlGroup label="Root">
          <input
            type="text"
            value={root || ''}
            onChange={(e) => onRootChange(e.target.value || undefined)}
            placeholder="Function..."
            className="w-32 h-8 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </ControlGroup>

        {/* Direction selector (for call graphs) */}
        {view === 'call' && (
          <ControlGroup label="Direction">
            <select
              value={direction}
              onChange={(e) => onDirectionChange(e.target.value as DirectionType)}
              className="w-24 h-8 pl-3 pr-8 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            >
              <option value="both">Both</option>
              <option value="callers">Callers</option>
              <option value="callees">Callees</option>
            </select>
          </ControlGroup>
        )}

        {/* Max nodes slider */}
        <ControlGroup label={`Limit: ${maxNodes === 500 ? 'All' : maxNodes}`}>
          <input
            type="range"
            min="20"
            max="500"
            step="20"
            value={maxNodes}
            onChange={(e) => onMaxNodesChange(parseInt(e.target.value, 10))}
            className="w-20 h-1"
          />
        </ControlGroup>

        {/* Layout selector */}
        <ControlGroup label="Layout">
          <select
            value={layout}
            onChange={(e) => onLayoutChange(e.target.value as LayoutType)}
            className="w-32 h-8 pl-3 pr-8 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="dagre">Hierarchical</option>
            <option value="cose-bilkent">Force</option>
            <option value="breadthfirst">Breadth-first</option>
            <option value="concentric">Concentric</option>
            <option value="circle">Circle</option>
            <option value="grid">Grid</option>
          </select>
        </ControlGroup>

        {/* Divider */}
        <div className="h-6 w-px bg-slate-200 dark:bg-slate-700 hidden sm:block" />

        {/* Toggle buttons */}
        <div className="flex items-center gap-4">
          <Toggle
            checked={showMetrics}
            onChange={onShowMetricsChange}
            label="Metrics"
            color="blue"
          />
          <Toggle
            checked={clustered}
            onChange={onClusteredChange}
            label="Cluster"
            color="emerald"
          />
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Refresh button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-sm font-medium text-white bg-blue-500 hover:bg-blue-600 rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg
              className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            Refresh
          </button>
        )}
      </div>
    </div>
  );
}

interface ControlGroupProps {
  label: string;
  children: React.ReactNode;
}

function ControlGroup({ label, children }: ControlGroupProps) {
  return (
    <div className="flex items-center gap-2">
      <label className="text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap">
        {label}
      </label>
      {children}
    </div>
  );
}

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  color: 'blue' | 'red' | 'emerald';
}

function Toggle({ checked, onChange, label, color }: ToggleProps) {
  const colorClasses = {
    blue: 'peer-checked:bg-blue-500',
    red: 'peer-checked:bg-red-500',
    emerald: 'peer-checked:bg-emerald-500',
  };

  return (
    <label className="inline-flex items-center gap-2 cursor-pointer select-none">
      <div className="relative">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="sr-only peer"
        />
        <div className={`w-8 h-4 bg-slate-200 dark:bg-slate-700 rounded-full peer ${colorClasses[color]} transition-colors`}>
          <div className={`absolute top-0.5 left-0.5 w-3 h-3 bg-white rounded-full shadow-sm transition-transform ${checked ? 'translate-x-4' : ''}`} />
        </div>
      </div>
      <span className="text-xs font-medium text-slate-600 dark:text-slate-400">
        {label}
      </span>
    </label>
  );
}

export default Controls;
