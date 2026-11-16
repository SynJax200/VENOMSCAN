"use client";

import { FileText, Loader2, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { ReportGenerator, ReportTable, useReports } from "@/components/report-tools";
import { Badge, Button, Card, CardHeader, Notice, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import type { Report, Scan } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [scanId, setScanId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const { reports, setReports, loading } = useReports();
  const [created, setCreated] = useState<Report | null>(null);

  useEffect(() => {
    api
      .get<Scan[]>("/api/scans?limit=200")
      .then((rows) => {
        const completed = rows.filter((row) => row.status === "completed");
        setScans(completed);
        if (completed.length) setScanId(completed[0].id);
      })
      .catch(() => {
        setScans([]);
        setError("Could not load completed scans");
      });
  }, []);

  const selected = useMemo(() => scans?.find((scan) => scan.id === scanId), [scanId, scans]);

  function onCreated(report: Report) {
    setCreated(report);
    setReports((rows) => [report, ...rows]);
  }

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Every format renders from one canonical model. Integrity is the SHA-256 of canonical JSON, so a report can be verified after download."
        actions={
          <Badge tone="bg-emerald-500/10 text-emerald-300 border-emerald-400/25">
            <ShieldCheck size={12} /> SHA-256 verifiable
          </Badge>
        }
      />

      {error ? <Notice tone="danger">{error}</Notice> : null}

      <Card>
        <CardHeader
          title="Generate a report"
          subtitle="Pick a completed scan, choose a format, then share a signed link or the raw file."
          action={<FileText size={15} className="text-slate-400" />}
        />
        {scans === null ? (
          <div className="px-5 py-4">
            <Skeleton className="h-10" />
          </div>
        ) : scans.length === 0 ? (
          <p className="px-5 py-8 text-center text-[12.5px] text-slate-400">
            Complete a scan first — reports are only generated for completed scans.
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
              <span className="text-[12px] text-slate-500">Scan</span>
              <select
                value={scanId}
                onChange={(event) => setScanId(event.target.value)}
                className="h-8 max-w-[420px] rounded-[7px] border border-line bg-panel px-2 text-[12px] text-ink"
              >
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.target_name} · {scan.profile} · {formatDate(scan.created_at)}
                  </option>
                ))}
              </select>
              {selected ? (
                <Badge tone="bg-white/5 text-slate-600 border-line">
                  {selected.findings_total} findings
                </Badge>
              ) : null}
            </div>
            {scanId ? <ReportGenerator scanId={scanId} onCreated={onCreated} /> : null}
          </>
        )}
        {created ? (
          <div className="px-5 pb-4">
            <Notice tone="success">
              {created.filename} generated · SHA-256 {created.sha256.slice(0, 24)}… · expires{" "}
              {formatDate(created.expires_at)}
            </Notice>
          </div>
        ) : null}
      </Card>

      <Card className="mt-4">
        <CardHeader
          title="Generated reports"
          subtitle="Signed links work without a session until they expire; downloads stay behind authentication."
          action={
            <Badge tone="bg-white/5 text-slate-600 border-line">
              {loading ? <Loader2 size={12} className="animate-spin" /> : reports.length} files
            </Badge>
          }
        />
        {loading ? (
          <div className="space-y-2 px-5 py-4">
            <Skeleton className="h-8" />
            <Skeleton className="h-8" />
          </div>
        ) : (
          <ReportTable reports={reports} />
        )}
      </Card>

      <p className="mt-3 text-[11px] text-slate-400">
        Signed URLs are HMAC-SHA256 over the report id and expiry, verified in constant time. Rotating
        SECRET_KEY invalidates every outstanding link.
      </p>

      <div className="mt-4">
        <Button variant="secondary" onClick={() => window.location.reload()} size="sm">
          Refresh list
        </Button>
      </div>
    </div>
  );
}
