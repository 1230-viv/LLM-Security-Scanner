import type { Severity } from "@/types";

interface Props {
  severity: Severity;
}

function SeverityBadge({ severity }: Props): JSX.Element {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

export default SeverityBadge;
