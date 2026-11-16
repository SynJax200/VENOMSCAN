"use client";

import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  Crosshair,
  Globe,
  Layers,
  Radar,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { PageHeader } from "@/components/app-shell";
import { ProfileBadge, StatusBadge } from "@/components/badges";
import { Button, Card, CardHeader, EmptyState, Notice, Progress, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { Dashboard } from "@/lib/types";
import { formatDate, relativeTime, severityHex, severityOrder } from "@/lib/utils";

const severityLabels: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export default function DashboardPage() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [splitBy, setSplitBy] = useState<"owasp" | "check">("owasp");

  useEffect(() => {
    api
      .get<Dashboard>("/api/dashboard")
      .then(setData)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load the dashboard"));
  }, []);

  if (error) {
    return (
      <Notice tone="danger">
        {error}{" "}
        <button className="font-semibold underline" onClick={() => window.location.reload()}>
          Retry
        </button>
      </Notice>
    );
  }

  if (!data) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-14 w-2/5" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-[104px]" />
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-[320px]" />
          <Skeleton className="h-[320px] lg:col-span-2" />
        </div>
      </div>
    );
  }

  const donut = severityOrder
    .map((key) => ({ name: severityLabels[key], key, value: data.severity[key] }))
    .filter((slice) => slice.value > 0);
  const maxTech = Math.max(1, ...data.technologies.map((tech) => tech.count));
  const split = splitBy === "check" ? data.by_check : data.by_owasp;
  const maxSplit = Math.max(1, ...split.map((slice) => slice.count));

  return (
    <div>
      <PageHeader
        eyebrow="Security overview"
        title="Your attack surface at a glance"
        description="Findings are grounded in evidence collected from verified targets. Passive coverage only — deeper modules expand with each phase."
        actions={
          <Link href="/targets">
            <Button>
              <Crosshair size={16} /> New assessment
            </Button>
          </Link>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          icon={<Radar size={17} />}
          label="Total scans"
          value={data.total_scans}
          hint={`${data.active_scans} active right now`}
        />
        <KpiCard
          icon={<CheckCircle2 size={17} />}
          label="Completed"
          value={data.completed_scans}
          hint="Finished with stored evidence"
        />
        <KpiCard
          icon={<Activity size={17} />}
          label="Active scans"
          value={data.active_scans}
          hint="Live telemetry streaming"
          accent={data.active_scans > 0}
        />
        <KpiCard
          icon={<ShieldAlert size={17} />}
          label="Open findings"
          value={data.total_findings}
          hint={`${data.severity.critical + data.severity.high} critical or high`}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Target overview"
            subtitle="Verified scope, scans and findings per target"
            action={
              <Link href="/targets" className="text-[12.5px] font-medium text-brand-ring hover:text-white">
                Manage
              </Link>
            }
          />
          {data.targets.length === 0 ? (
            <EmptyState
              icon={<Globe size={18} />}
              title="No targets yet"
              description="Add a target and complete ownership verification before scanning."
              action={
                <Link href="/targets">
                  <Button size="sm">Add a target</Button>
                </Link>
              }
            />
          ) : (
            <div className="divide-y divide-line">
              {data.targets.map((target) => (
                <Link
                  key={target.id}
                  href={`/targets/${target.id}`}
                  className="flex items-center justify-between gap-3 px-5 py-3 transition hover:bg-white/[0.05]"
                >
                  <div className="min-w-0">
                    <p className="truncate text-[13.5px] font-medium text-ink">{target.name}</p>
                    <p className="truncate text-[12px] text-slate-500">{target.url}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-4">
                    <div className="text-right">
                      <p className="text-[12.5px] font-medium tabular-nums text-ink">{target.scans} scans</p>
                      <p className="text-[11.5px] tabular-nums text-slate-500">{target.findings} findings</p>
                    </div>
                    <div className="flex w-[104px] justify-end">
                      {target.last_status ? <StatusBadge status={target.last_status} /> : null}
                    </div>
                    <span className="w-[70px] text-right text-[11.5px] text-slate-500">
                      {target.last_scan_at ? relativeTime(target.last_scan_at) : "never"}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                <Layers size={15} className="text-brand-ring" /> Vulnerability split
              </span>
            }
            subtitle="Stored findings grouped by OWASP category or check"
          />
          <div className="px-5 py-4">
            <div className="mb-4 inline-flex rounded-[7px] border border-line bg-white/[0.03] p-0.5">
              {(["owasp", "check"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setSplitBy(mode)}
                  className={`rounded-[5px] px-2.5 py-1 text-[11.5px] font-medium transition ${
                    splitBy === mode ? "bg-brand text-white" : "text-slate-500 hover:text-white"
                  }`}
                >
                  {mode === "owasp" ? "OWASP" : "Check"}
                </button>
              ))}
            </div>
            {split.length === 0 ? (
              <p className="py-6 text-center text-[12.5px] text-slate-400">
                Distribution appears after the first scan stores findings.
              </p>
            ) : (
              <ul className="space-y-3">
                {split.map((slice) => (
                  <li key={slice.name}>
                    <div className="mb-1 flex items-center justify-between gap-2 text-[12px]">
                      <span className="truncate font-medium text-ink" title={slice.name}>
                        {slice.name}
                      </span>
                      <span className="shrink-0 tabular-nums text-slate-500">{slice.count}</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-brand to-accent"
                        style={{ width: `${(slice.count / maxSplit) * 100}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Severity distribution" subtitle="Across all stored findings" />
          <div className="px-5 pb-5 pt-4">
            {data.total_findings === 0 ? (
              <EmptyState
                icon={<ShieldAlert size={18} />}
                title="No findings yet"
                description="Run a passive scan against a verified target to build your first baseline."
              />
            ) : (
              <>
                <div className="relative mx-auto h-[188px] w-full max-w-[240px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={donut}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={58}
                        outerRadius={80}
                        paddingAngle={3}
                        stroke="none"
                        isAnimationActive={false}
                      >
                        {donut.map((slice) => (
                          <Cell key={slice.key} fill={severityHex[slice.key]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          borderRadius: 10,
                          border: "1px solid #26262D",
                          background: "#121216",
                          color: "#F4F4F6",
                          fontSize: 12,
                          boxShadow: "0 12px 32px rgba(0,0,0,0.5)",
                        }}
                        itemStyle={{ color: "#F4F4F6" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-[26px] font-semibold leading-none text-ink">
                      {data.total_findings}
                    </span>
                    <span className="mt-1 text-[11px] font-medium uppercase tracking-[0.1em] text-slate-400">
                      findings
                    </span>
                  </div>
                </div>
                <ul className="mt-2 space-y-1.5">
                  {severityOrder.map((key) => (
                    <li key={key} className="flex items-center justify-between text-[12.5px]">
                      <span className="flex items-center gap-2 text-slate-600">
                        <span
                          className="h-2 w-2 rounded-full"
                          style={{ backgroundColor: severityHex[key] }}
                        />
                        {severityLabels[key]}
                      </span>
                      <span className="font-medium tabular-nums text-ink">{data.severity[key]}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader
            title="Recent scan activity"
            subtitle="Latest assessments across your targets"
            action={
              <Link href="/scans" className="text-[12.5px] font-medium text-brand-ring hover:text-white">
                View all
              </Link>
            }
          />
          {data.recent_scans.length === 0 ? (
            <EmptyState
              icon={<Radar size={18} />}
              title="Nothing scanned yet"
              description="Add a target, verify ownership with DNS, a well-known file or an attestation, then start a scan."
              action={
                <Link href="/targets">
                  <Button size="sm">Add your first target</Button>
                </Link>
              }
            />
          ) : (
            <div className="divide-y divide-line">
              {data.recent_scans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex flex-col gap-2 px-5 py-3.5 transition hover:bg-white/[0.05]"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-[13.5px] font-medium text-ink">{scan.target_name}</p>
                      <p className="truncate text-[12px] text-slate-500">{scan.target_url}</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <ProfileBadge profile={scan.profile} />
                      <StatusBadge status={scan.status} />
                      <ArrowUpRight size={14} className="text-slate-300" />
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex-1">
                      <Progress
                        value={scan.status === "completed" ? 100 : scan.progress}
                        tone={
                          scan.status === "failed"
                            ? "bg-severity-critical"
                            : scan.status === "cancelled"
                              ? "bg-slate-400"
                              : scan.status === "completed"
                                ? "bg-emerald-500"
                                : "bg-brand"
                        }
                      />
                    </div>
                    <span className="shrink-0 text-[11.5px] tabular-nums text-slate-500">
                      {scan.findings_total} findings · {relativeTime(scan.created_at)}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Technology distribution" subtitle="Fingerprints observed in scans" />
          <div className="px-5 py-4">
            {data.technologies.length === 0 ? (
              <p className="py-6 text-center text-[12.5px] text-slate-400">
                Technology fingerprints appear after the first completed scan.
              </p>
            ) : (
              <ul className="space-y-3">
                {data.technologies.map((tech) => (
                  <li key={tech.name}>
                    <div className="mb-1 flex items-center justify-between text-[12.5px]">
                      <span className="font-medium text-ink">{tech.name}</span>
                      <span className="tabular-nums text-slate-500">{tech.count}</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-brand to-accent"
                        style={{ width: `${(tech.count / maxTech) * 100}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                <Sparkles size={15} className="text-brand-ring" /> Security insights
              </span>
            }
            subtitle="Deterministic, evidence-based reading of your scan data"
          />
          <div className="space-y-3 px-5 py-4">
            {data.insights.map((insight, index) => (
              <div key={index} className="flex gap-3 rounded-[8px] border border-line bg-white/[0.03] px-3.5 py-3">
                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-soft text-[11px] font-semibold text-brand-ring">
                  {index + 1}
                </span>
                <p className="text-[13px] leading-relaxed text-slate-600">{insight}</p>
              </div>
            ))}
            {data.severity.critical + data.severity.high > 0 ? (
              <Link
                href={`/findings?severity=critical`}
                className="inline-flex items-center gap-1 text-[12.5px] font-medium text-brand-ring hover:text-white"
              >
                Triage critical findings <ArrowUpRight size={13} />
              </Link>
            ) : null}
          </div>
        </Card>
      </div>

      {data.recent_scans.length > 0 ? (
        <p className="mt-6 text-[11.5px] text-slate-400">
          Last activity {formatDate(data.recent_scans[0].created_at)} · All timestamps in your local timezone.
        </p>
      ) : null}
    </div>
  );
}

function KpiCard({
  icon,
  label,
  value,
  hint,
  accent = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  hint: string;
  accent?: boolean;
}) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <p className="text-[12px] font-medium uppercase tracking-[0.08em] text-slate-500">{label}</p>
        <span
          className={`flex h-8 w-8 items-center justify-center rounded-[8px] ${
            accent ? "bg-accent text-white shadow-glow" : "bg-brand-soft text-brand-ring"
          }`}
        >
          {icon}
        </span>
      </div>
      <p className="mt-3 text-[28px] font-semibold leading-none tracking-tight text-ink tabular-nums">
        {value}
      </p>
      <p className="mt-2 text-[11.5px] text-slate-400">{hint}</p>
    </Card>
  );
}
