"use client";

import { ArrowRight, Filter, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { SeverityBadge, VerificationBadge } from "@/components/badges";
import { Card, EmptyState, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { cn, formatDate, severityOrder } from "@/lib/utils";

export default function FindingsPage() {
  return (
    <Suspense fallback={<FindingsSkeleton />}>
      <FindingsInner />
    </Suspense>
  );
}

function FindingsSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-14 w-2/5" />
      <Skeleton className="h-[420px]" />
    </div>
  );
}

function FindingsInner() {
  const searchParams = useSearchParams();
  const scanFilter = searchParams.get("scan");
  const initialSeverity = searchParams.get("severity");
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [severity, setSeverity] = useState<string>(initialSeverity ?? "all");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Finding[]>("/api/findings?limit=500")
      .then(setFindings)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load findings"));
  }, []);

  const scoped = useMemo(
    () => (findings ?? []).filter((finding) => (scanFilter ? finding.scan_id === scanFilter : true)),
    [findings, scanFilter],
  );
  const visible = useMemo(
    () => (severity === "all" ? scoped : scoped.filter((finding) => finding.severity === severity)),
    [scoped, severity],
  );
  const counts = useMemo(() => {
    const map: Record<string, number> = { all: scoped.length };
    for (const level of severityOrder) map[level] = scoped.filter((f) => f.severity === level).length;
    return map;
  }, [scoped]);

  return (
    <div>
      <PageHeader
        eyebrow="Findings"
        title="Evidence-backed results"
        description="Each result is tied to the response that produced it. Severity is derived from impact and confidence — never invented."
        actions={
          <Link
            href="/scans"
            className="inline-flex h-10 items-center gap-2 rounded-[8px] border border-line bg-panel px-4 text-sm font-medium text-ink hover:bg-white/[0.04]"
          >
            Open scans
          </Link>
        }
      />

      {error ? <Notice tone="danger">{error}</Notice> : null}

      {scanFilter ? (
        <div className="mb-4">
          <Notice tone="info">
            Showing findings for a single scan.{" "}
            <Link href="/findings" className="font-semibold underline">
              Clear scan filter
            </Link>
          </Notice>
        </div>
      ) : null}

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        <span className="mr-1 inline-flex items-center gap-1 text-[11.5px] font-medium text-slate-400">
          <Filter size={12} /> Severity
        </span>
        {(["all", ...severityOrder] as const).map((level) => (
          <button
            key={level}
            onClick={() => setSeverity(level)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11.5px] font-medium capitalize transition",
              severity === level
                ? "border-brand bg-brand-soft text-brand-ring"
                : "border-line bg-panel text-slate-500 hover:border-slate-300",
            )}
          >
            {level}
            {findings ? (
              <span className="ml-1.5 tabular-nums text-[10.5px] text-slate-400">{counts[level] ?? 0}</span>
            ) : null}
          </button>
        ))}
      </div>

      <Card>
        {!findings ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-14" />
            ))}
          </div>
        ) : visible.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert size={18} />}
            title="No findings in this view"
            description="Run a scan against a verified target or widen the severity filter."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-sm">
              <thead>
                <tr className="table-head">
                  <th className="px-5 py-2.5">Finding</th>
                  <th className="px-4 py-2.5">Severity</th>
                  <th className="px-4 py-2.5">Verification</th>
                  <th className="px-4 py-2.5 text-right">Risk</th>
                  <th className="px-4 py-2.5">Found</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {visible.map((finding) => (
                  <tr key={finding.id} className="transition hover:bg-white/[0.03]">
                    <td className="px-5 py-3">
                      <Link href={`/findings/${finding.id}`} className="block max-w-[520px]">
                        <span className="flex items-center gap-2">
                          <span className="truncate text-[13px] font-medium text-ink">
                            {finding.title}
                          </span>
                          {finding.occurrences > 1 ? (
                            <span className="shrink-0 rounded-full border border-line bg-white/[0.04] px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-slate-500">
                              ×{finding.occurrences}
                            </span>
                          ) : null}
                        </span>
                        <span className="block truncate font-mono text-[11px] text-slate-400">
                          {finding.check_id} · {finding.url}
                        </span>
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <VerificationBadge status={finding.verification_status} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className="rounded-[6px] bg-white/[0.04] px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-slate-600">
                        {finding.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[11.5px] text-slate-500">{formatDate(finding.created_at)}</td>
                    <td className="px-4 py-3 text-right">
                      <Link
                        href={`/findings/${finding.id}`}
                        className="inline-flex items-center gap-1 text-[12px] font-medium text-brand-ring"
                      >
                        Details <ArrowRight size={13} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
