import type { GraphNode } from '../types/graph';

export interface NodeDetailsProps {
  node: GraphNode | null;
  onClose?: () => void;
  onNavigate?: (filePath: string, line: number) => void;
}

export function NodeDetails({ node, onClose, onNavigate }: NodeDetailsProps) {
  if (!node) {
    return (
      <div className="h-full flex items-center justify-center p-6">
        <p className="text-sm text-slate-400 dark:text-slate-500">Select a node to view details</p>
      </div>
    );
  }

  const handleNavigate = () => {
    onNavigate?.(node.file_path, node.line);
  };

  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white leading-tight">
            {node.label}
          </h3>
          <span className="inline-block mt-1.5 px-2 py-0.5 text-[10px] font-medium rounded-full bg-blue-50 text-blue-600 dark:bg-blue-950 dark:text-blue-400 uppercase tracking-wide">
            {node.kind}
          </span>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="p-1 -mr-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 rounded transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Location */}
      <Section title="Location">
        <button
          onClick={handleNavigate}
          className="group flex items-center gap-1.5 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
        >
          <svg className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
          <span className="truncate font-mono">{node.file_path}:{node.line}</span>
        </button>
      </Section>

      {/* Metrics */}
      {node.metrics && (
        <Section title="Metrics">
          <div className="grid grid-cols-2 gap-2">
            <MetricCard
              label="Lines"
              value={node.metrics.loc}
              color="slate"
            />
            <MetricCard
              label="Cyclomatic"
              value={node.metrics.cyclomatic}
              color={getComplexityColor(node.metrics.cyclomatic)}
            />
            <MetricCard
              label="Cognitive"
              value={node.metrics.cognitive}
              color={getComplexityColor(node.metrics.cognitive)}
            />
            <MetricCard
              label="Calls"
              value={node.metrics.call_count}
              color="slate"
            />
            <MetricCard
              label="Callers"
              value={node.metrics.caller_count}
              color="slate"
            />
          </div>
        </Section>
      )}

      {/* Code Excerpt */}
      {node.excerpt && (
        <Section title="Code">
          <pre className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-3 text-[11px] leading-relaxed overflow-auto max-h-48 font-mono text-slate-700 dark:text-slate-300">
            <code>{node.excerpt}</code>
          </pre>
        </Section>
      )}
    </div>
  );
}

interface SectionProps {
  title: string;
  children: React.ReactNode;
}

function Section({ title, children }: SectionProps) {
  return (
    <div>
      <h4 className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">
        {title}
      </h4>
      {children}
    </div>
  );
}

interface MetricCardProps {
  label: string;
  value: number;
  color: 'slate' | 'green' | 'yellow' | 'orange' | 'red';
}

function MetricCard({ label, value, color }: MetricCardProps) {
  const colorClasses = {
    slate: 'bg-slate-50 dark:bg-slate-800/50 text-slate-700 dark:text-slate-300',
    green: 'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400',
    yellow: 'bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400',
    orange: 'bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400',
    red: 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-400',
  };

  return (
    <div className={`rounded-lg px-3 py-2 ${colorClasses[color]}`}>
      <div className="text-[10px] opacity-70 uppercase tracking-wide">{label}</div>
      <div className="text-lg font-semibold leading-tight">{value}</div>
    </div>
  );
}

function getComplexityColor(value: number): MetricCardProps['color'] {
  if (value > 20) return 'red';
  if (value > 15) return 'orange';
  if (value > 10) return 'yellow';
  return 'green';
}

export default NodeDetails;
