import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const then = new Date(value).getTime();
  const diff = Date.now() - then;
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

export const severityHex: Record<string, string> = {
  critical: "#FF3B5C",
  high: "#FF8A3D",
  medium: "#FFC53D",
  low: "#33B5FF",
  info: "#8B8B95",
};

export const phaseLabels: Record<string, string> = {
  queued: "Queued",
  authorizing: "Authorizing",
  recon: "Reconnaissance",
  crawling: "Crawling",
  analyzing: "Analysis",
  verifying: "Verification",
  correlating: "Correlation",
  ai_enriching: "AI enrichment",
  reporting: "Reporting",
};

export const statusTone: Record<string, string> = {
  queued: "bg-white/5 text-slate-600 border-line",
  running: "bg-brand/10 text-brand-ring border-brand-ring/25",
  completed: "bg-emerald-500/10 text-emerald-300 border-emerald-400/25",
  failed: "bg-red-500/10 text-red-300 border-red-400/25",
  cancelled: "bg-white/5 text-slate-600 border-line",
  verified: "bg-emerald-500/10 text-emerald-300 border-emerald-400/25",
  suspected: "bg-amber-500/10 text-amber-300 border-amber-400/25",
  rejected: "bg-white/5 text-slate-600 border-line",
};

export function truncate(value: string, max = 72): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}
