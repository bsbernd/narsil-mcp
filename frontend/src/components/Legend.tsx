export function Legend() {
  return (
    <div className="bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 px-5 py-3">
      <div className="flex flex-wrap gap-x-10 gap-y-3 text-[11px]">
        {/* Node types */}
        <LegendGroup title="Nodes">
          <LegendItem color="#64748b" label="Default" />
          <LegendItem color="#8b5cf6" label="Class" />
          <LegendItem color="#0ea5e9" label="File" />
          <LegendItem color="#a855f7" shape="circle" label="Ref" />
        </LegendGroup>

        {/* Complexity - now full color */}
        <LegendGroup title="Complexity">
          <LegendItem color="#22c55e" label="Low" />
          <LegendItem color="#eab308" label="Med" />
          <LegendItem color="#f97316" label="High" />
          <LegendItem color="#dc2626" label="Crit" />
        </LegendGroup>

        {/* Edge types */}
        <LegendGroup title="Edges">
          <LegendItem color="#3b82f6" shape="line" label="Call" arrowType="triangle" />
          <LegendItem color="#10b981" shape="dashed" label="Import" arrowType="diamond" />
          <LegendItem color="#a855f7" shape="dotted" label="Ref" arrowType="vee" />
          <LegendItem color="#f59e0b" shape="line" label="Flow" arrowType="chevron" />
          <LegendItem color="#dc2626" shape="dashed" label="Cycle" />
        </LegendGroup>

        {/* Call types */}
        <LegendGroup title="Call Types">
          <LegendItem color="#3b82f6" shape="line" label="Direct" />
          <LegendItem color="#6366f1" shape="dashed" label="Async" />
          <LegendItem color="#8b5cf6" shape="dotted" label="Closure" />
        </LegendGroup>
      </div>
    </div>
  );
}

interface LegendGroupProps {
  title: string;
  children: React.ReactNode;
}

function LegendGroup({ title, children }: LegendGroupProps) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
        {title}
      </span>
      <div className="flex items-center gap-2.5">
        {children}
      </div>
    </div>
  );
}

interface LegendItemProps {
  color?: string;
  border?: string;
  borderStyle?: 'solid' | 'dashed';
  shape?: 'square' | 'circle' | 'line' | 'dashed' | 'dotted';
  arrowType?: 'triangle' | 'diamond' | 'vee' | 'chevron';
  label: string;
}

function LegendItem({ color, border, borderStyle = 'solid', shape = 'square', arrowType, label }: LegendItemProps) {
  // Line shapes with optional arrows
  if (shape === 'line' || shape === 'dashed' || shape === 'dotted') {
    const dashArray = shape === 'dashed' ? '4,2' : shape === 'dotted' ? '2,2' : 'none';

    const renderArrow = () => {
      if (!arrowType) return null;

      switch (arrowType) {
        case 'triangle':
          return <polygon points="22,4 18,7 18,1" fill={color} />;
        case 'diamond':
          return <polygon points="22,4 19,6 16,4 19,2" fill={color} />;
        case 'vee':
          return <polyline points="18,1 22,4 18,7" fill="none" stroke={color} strokeWidth="1.5" />;
        case 'chevron':
          return <polyline points="17,2 21,4 17,6" fill="none" stroke={color} strokeWidth="2" />;
        default:
          return null;
      }
    };

    return (
      <div className="flex items-center gap-1.5">
        <svg width={arrowType ? 24 : 18} height="8" className="flex-shrink-0">
          <line
            x1="0"
            y1="4"
            x2={arrowType ? 18 : 18}
            y2="4"
            stroke={color}
            strokeWidth="2"
            strokeDasharray={dashArray}
          />
          {renderArrow()}
        </svg>
        <span className="text-slate-600 dark:text-slate-400">{label}</span>
      </div>
    );
  }

  // Node shapes
  const isCircle = shape === 'circle';
  const size = isCircle ? 10 : 12;
  const radius = isCircle ? 5 : 2;

  return (
    <div className="flex items-center gap-1.5">
      <svg width={size} height={size} className="flex-shrink-0">
        {isCircle ? (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={(size / 2) - (border ? 1 : 0)}
            fill={color || 'transparent'}
            stroke={border}
            strokeWidth={border ? 2 : 0}
            strokeDasharray={borderStyle === 'dashed' ? '2,1' : 'none'}
          />
        ) : (
          <rect
            x={border ? 1 : 0}
            y={border ? 1 : 0}
            width={border ? size - 2 : size}
            height={border ? size - 2 : size}
            rx={radius}
            ry={radius}
            fill={color || 'transparent'}
            stroke={border}
            strokeWidth={border ? 2 : 0}
            strokeDasharray={borderStyle === 'dashed' ? '2,1' : 'none'}
          />
        )}
      </svg>
      <span className="text-slate-600 dark:text-slate-400">{label}</span>
    </div>
  );
}

export default Legend;
