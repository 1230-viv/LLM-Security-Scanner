import type { Severity } from "@/types";

interface Props {
  severity: Severity;
}

function SeverityBadge({ severity }: Props): JSX.Element {
  const toneBySeverity: Record<Severity, string> = {
    high: "border-red-200 bg-red-50 text-red-700",
    medium: "border-amber-200 bg-amber-50 text-amber-700",
    low: "border-emerald-200 bg-emerald-50 text-emerald-700",
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.08em] ${toneBySeverity[severity]}`}
    >
      {severity}
    </span>
  );
}

export default SeverityBadge;
