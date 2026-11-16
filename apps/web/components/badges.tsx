import { Badge } from "@/components/ui";
import { severityHex, statusTone } from "@/lib/utils";

const severityBackground: Record<string, string> = {
  critical: "bg-severity-critical/10 text-severity-critical border-severity-critical/25",
  high: "bg-severity-high/10 text-severity-high border-severity-high/25",
  medium: "bg-severity-medium/10 text-severity-medium border-severity-medium/25",
  low: "bg-severity-low/10 text-severity-low border-severity-low/25",
  info: "bg-severity-info/10 text-severity-info border-severity-info/25",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge tone={severityBackground[severity] ?? "bg-slate-100 text-slate-600 border-slate-200"}>
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: severityHex[severity] ?? "#64748B" }}
      />
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={statusTone[status] ?? "bg-slate-100 text-slate-600 border-slate-200"}>{status}</Badge>;
}

export function VerificationBadge({ status }: { status: string }) {
  return <Badge tone={statusTone[status] ?? "bg-slate-100 text-slate-600 border-slate-200"}>{status}</Badge>;
}

export function ProfileBadge({ profile }: { profile: string }) {
  const tones: Record<string, string> = {
    passive: "bg-slate-100 text-slate-700 border-slate-200",
    safe: "bg-blue-500/10 text-blue-300 border-blue-400/25",
    active: "bg-orange-500/10 text-orange-300 border-orange-400/25",
  };
  return <Badge tone={tones[profile] ?? tones.safe}>{profile}</Badge>;
}
