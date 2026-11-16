"use client";

import { ArrowRightLeft, Download, Loader2, Radar, ShieldQuestion, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";

import { SeverityBadge } from "@/components/badges";
import { ReportsCard } from "@/components/report-tools";
import { Badge } from "@/components/ui";
import { Card, CardHeader } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { IntelReport, Scan, ScanCompare } from "@/lib/types";
import { cn, formatDate } from "@/lib/utils";

export function CompareCard({ scanId, targetId }: { scanId: string; targetId: string }) {
  const [options, setOptions] = useState<Scan[]>([]);
  const [other, setOther] = useState("");
  const [result, setResult] = useState<ScanCompare | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Scan[]>(`/api/scans?target_id=${targetId}`)
      .then((rows) => {
        const completed = rows.filter((row) => row.status === "completed" && row.id !== scanId);
        setOptions(completed);
        if (completed.length) setOther(completed[0].id);
      })
      .catch(() => setOptions([]));
  }, [scanId, targetId]);

  useEffect(() => {
    if (!other) return;
    setBusy(true);
    setError(null);
    api
      .get<ScanCompare>(`/api/scans/${scanId}/compare?other=${other}`)
      .then(setResult)
      .catch((err) => {
        setResult(null);
        setError(err instanceof ApiError ? err.detail : "Could not compare these scans");
      })
      .finally(() => setBusy(false));
  }, [other, scanId]);

  const sections: { key: "new" | "fixed" | "persisting"; title: string; tone: string }[] = [
    { key: "new", title: "New", tone: "text-red-300" },
    { key: "fixed", title: "Fixed", tone: "text-emerald-300" },
    { key: "persisting", title: "Persisting", tone: "text-amber-300" },
  ];

  return (
    <Card className="mt-4">
      <CardHeader
        title="Compare scans"
        subtitle="Findings are matched by dedup key so you can see what appeared, what was fixed and what persisted."
        action={
          <span className="inline-flex items-center gap-1 text-[11.5px] text-slate-400">
            <ArrowRightLeft size={12} />
            {result ? `${result.counts.new} new · ${result.counts.fixed} fixed · ${result.counts.persisting} persisting` : "—"}
          </span>
        }
      />
      {options.length === 0 ? (
        <p className="px-5 py-8 text-center text-[12.5px] text-slate-400">
          Run another scan against this target to enable comparison.
        </p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 px-5 py-4">
            <span className="text-[12px] text-slate-500">Baseline</span>
            <select
              value={other}
              onChange={(event) => setOther(event.target.value)}
              className="h-8 rounded-[7px] border border-line bg-panel px-2 text-[12px] text-ink"
            >
              {options.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.profile} · {formatDate(scan.created_at)}
                </option>
              ))}
            </select>
            {busy ? <Loader2 size={14} className="animate-spin text-slate-400" /> : null}
            {result ? (
              <span className="ml-auto text-[11px] text-slate-400">
                base: {result.base_label.trim()} → {result.other_label.trim()}
              </span>
            ) : null}
          </div>
          {error ? <p className="px-5 pb-4 text-[12px] text-red-300">{error}</p> : null}
          {result ? (
            <div className="grid gap-px border-t border-line bg-line md:grid-cols-3">
              {sections.map(({ key, title, tone }) => (
                <div key={key} className="bg-panel px-5 py-4">
                  <p className={cn("mb-2 text-[11px] font-semibold uppercase tracking-[0.1em]", tone)}>
                    {title} ({result.counts[key]})
                  </p>
                  {result[key].length === 0 ? (
                    <p className="text-[12px] text-slate-400">None</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {result[key].slice(0, 8).map((finding) => (
                        <li key={finding.id} className="flex items-start gap-1.5">
                          <SeverityBadge severity={finding.severity} />
                          <span className="min-w-0 flex-1 truncate text-[11.5px] text-slate-600" title={finding.title}>
                            {finding.title}
                          </span>
                        </li>
                      ))}
                      {result[key].length > 8 ? (
                        <li className="text-[11px] text-slate-400">+{result[key].length - 8} more</li>
                      ) : null}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          ) : null}
        </>
      )}
    </Card>
  );
}

export function IntelCard({ scanId }: { scanId: string }) {
  const [intel, setIntel] = useState<IntelReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<IntelReport>(`/api/scans/${scanId}/intel`)
      .then(setIntel)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load CVE intelligence"));
  }, [scanId]);

  return (
    <Card className="mt-4">
      <CardHeader
        title="Known CVEs for detected technologies"
        subtitle="Offline curated snapshot. Version-range matches are triage input, not proof of exploitability."
        action={
          <span className="inline-flex items-center gap-1 text-[11.5px] text-slate-400">
            <Radar size={12} /> {intel ? `snapshot ${intel.snapshot_version}` : "—"}
          </span>
        }
      />
      {error ? <p className="px-5 py-6 text-[12.5px] text-red-300">{error}</p> : null}
      {!error && intel && intel.matches.length === 0 ? (
        <p className="flex items-center justify-center gap-1.5 px-5 py-8 text-center text-[12.5px] text-slate-400">
          <ShieldQuestion size={14} /> No snapshot CVEs matched the detected technology versions.
        </p>
      ) : null}
      {intel && intel.matches.length > 0 ? (
        <ul className="divide-y divide-line">
          {intel.matches.map((match) => (
            <li key={`${match.product}-${match.cve.id}`} className="px-5 py-3.5">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={match.cve.severity} />
                <span className="text-[12.5px] font-semibold text-ink">{match.cve.id}</span>
                <Badge tone="bg-white/5 text-slate-600 border-line">
                  {match.technology}
                  {match.version ? ` ${match.version}` : ""}
                </Badge>
                {match.cve.cvss !== null ? (
                  <span className="text-[11px] tabular-nums text-slate-400">CVSS {match.cve.cvss.toFixed(1)}</span>
                ) : null}
                {match.version_unknown ? (
                  <span className="inline-flex items-center gap-1 text-[10.5px] text-amber-300">
                    <Sparkles size={11} /> version unknown — verify manually
                  </span>
                ) : null}
              </div>
              <p className="mt-1.5 text-[12px] text-slate-600">{match.cve.summary}</p>
              <div className="mt-1 flex flex-wrap gap-2 text-[10.5px] text-slate-400">
                {match.cve.cwe.map((cwe) => (
                  <span key={cwe} className="font-mono">
                    {cwe}
                  </span>
                ))}
                {match.cve.refs.map((ref) => (
                  <a key={ref} href={ref} target="_blank" rel="noreferrer" className="underline hover:text-brand-ring">
                    advisory
                  </a>
                ))}
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </Card>
  );
}

export function ScanExtras({ scanId, targetId }: { scanId: string; targetId: string }) {
  return (
    <>
      <ReportsCard scanId={scanId} />
      <CompareCard scanId={scanId} targetId={targetId} />
      <IntelCard scanId={scanId} />
      <Card className="mt-4">
        <CardHeader
          title="Issue-tracker handoff"
          subtitle="Export this scan as a Burp Suite XML file. Outbound imports are scope-checked; exports carry the same findings and evidence."
          action={
            <a
              href={`/api/scans/${scanId}/integrations/burp/export`}
              className="inline-flex h-8 items-center gap-1 rounded-[7px] border border-line px-2.5 text-[11.5px] text-slate-600 transition hover:border-slate-400 hover:text-ink"
            >
              <Download size={12} /> Burp XML
            </a>
          }
        />
      </Card>
    </>
  );
}
