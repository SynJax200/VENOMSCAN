"use client";

import { ArrowRight, Play, Radar } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { ProfileBadge, StatusBadge } from "@/components/badges";
import { ScanWizard } from "@/components/scan-wizard";
import { Button, Card, EmptyState, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { Scan, Target } from "@/lib/types";
import { cn, formatDate } from "@/lib/utils";

const filters = ["all", "running", "completed", "failed"] as const;
type Filter = (typeof filters)[number];

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const [wizard, setWizard] = useState(false);

  useEffect(() => {
    Promise.all([api.get<Scan[]>("/api/scans"), api.get<Target[]>("/api/targets")])
      .then(([scanData, targetData]) => {
        setScans(scanData);
        setTargets(targetData);
      })
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load scans"));
  }, []);

  const visible = useMemo(() => {
    if (!scans) return [];
    if (filter === "all") return scans;
    if (filter === "running") return scans.filter((scan) => scan.status === "queued" || scan.status === "running");
    return scans.filter((scan) => scan.status === filter);
  }, [scans, filter]);

  return (
    <div>
      <PageHeader
        eyebrow="Assessments"
        title="Scans"
        description="Every scan records its profile, authorization and full event timeline."
        actions={
          <Button onClick={() => setWizard(true)}>
            <Play size={16} /> New scan
          </Button>
        }
      />

      {error ? <Notice tone="danger">{error}</Notice> : null}

      <div className="mb-4 inline-flex rounded-[9px] border border-line bg-panel p-1">
        {filters.map((value) => (
          <button
            key={value}
            onClick={() => setFilter(value)}
            className={cn(
              "rounded-[7px] px-3 py-1.5 text-[12.5px] font-medium capitalize transition",
              filter === value ? "bg-brand-soft text-brand-ring" : "text-slate-500 hover:text-ink",
            )}
          >
            {value}
          </button>
        ))}
      </div>

      <Card>
        {!scans ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-14" />
            ))}
          </div>
        ) : visible.length === 0 ? (
          <EmptyState
            icon={<Radar size={18} />}
            title={scans.length === 0 ? "No scans yet" : "No scans match this filter"}
            description={
              scans.length === 0
                ? "Verify a target, then start a passive or safe scan to collect a baseline."
                : "Try another status filter or start a fresh scan."
            }
            action={
              scans.length === 0 ? <Button size="sm" onClick={() => setWizard(true)}>Start a scan</Button> : undefined
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] border-collapse text-sm">
              <thead>
                <tr className="table-head">
                  <th className="px-5 py-2.5">Target</th>
                  <th className="px-4 py-2.5">Profile</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5 text-right">Findings</th>
                  <th className="px-4 py-2.5">Started</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {visible.map((scan) => (
                  <tr key={scan.id} className="transition hover:bg-white/[0.03]">
                    <td className="px-5 py-3">
                      <Link href={`/scans/${scan.id}`} className="block">
                        <p className="text-[13px] font-medium text-ink">{scan.target_name}</p>
                        <p className="max-w-[320px] truncate font-mono text-[11px] text-slate-400">
                          {scan.target_url}
                        </p>
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <ProfileBadge profile={scan.profile} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[13px] text-slate-600">
                      {scan.findings_total}
                    </td>
                    <td className="px-4 py-3 text-[12px] text-slate-500">{formatDate(scan.created_at)}</td>
                    <td className="px-4 py-3 text-right">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="inline-flex items-center gap-1 text-[12px] font-medium text-brand-ring hover:text-white"
                      >
                        Open <ArrowRight size={13} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <ScanWizard open={wizard} onClose={() => setWizard(false)} targets={targets} />
    </div>
  );
}
