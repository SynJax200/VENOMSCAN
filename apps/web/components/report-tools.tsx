"use client";

import {
  Copy,
  Download,
  ExternalLink,
  FileCode2,
  FileJson,
  FileText,
  FileType2,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui";
import { Button, Card, CardHeader, Notice } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { copyText } from "@/lib/clipboard";
import type { Report, ReportFormat } from "@/lib/types";
import { cn, formatDate, relativeTime } from "@/lib/utils";

const formats: { value: ReportFormat; label: string; icon: typeof FileJson; hint: string }[] = [
  { value: "json", label: "JSON", icon: FileJson, hint: "Canonical machine model" },
  { value: "markdown", label: "Markdown", icon: FileText, hint: "For tickets and wikis" },
  { value: "html", label: "HTML", icon: FileCode2, hint: "Print-ready standalone page" },
  { value: "pdf", label: "PDF", icon: FileType2, hint: "Client-ready document" },
];

export function formatIcon(format: string) {
  return formats.find((item) => item.value === format)?.icon ?? FileJson;
}

export function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function ReportTable({
  reports,
  empty = "No reports generated yet.",
}: {
  reports: Report[];
  empty?: string;
}) {
  const [copied, setCopied] = useState<string | null>(null);

  async function copyLink(report: Report) {
    const url = `${window.location.origin}${report.signed_url}`;
    if (await copyText(url)) {
      setCopied(report.id);
      window.setTimeout(() => setCopied(null), 1600);
    } else {
      // Last resort for browsers that block the clipboard API entirely.
      try {
        window.prompt("Signed link", url);
      } catch {
        // Some embedded webviews disable prompt(); the link stays in the table.
      }
    }
  }

  if (reports.length === 0) {
    return <p className="px-5 py-8 text-center text-[12.5px] text-slate-400">{empty}</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] border-collapse text-sm">
        <thead>
          <tr className="table-head">
            <th className="px-5 py-2.5">Report</th>
            <th className="px-4 py-2.5">Format</th>
            <th className="px-4 py-2.5">Integrity</th>
            <th className="px-4 py-2.5">Created</th>
            <th className="px-4 py-2.5">Expires</th>
            <th className="px-4 py-2.5 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {reports.map((report) => {
            const Icon = formatIcon(report.format);
            return (
              <tr key={report.id}>
                <td className="max-w-[280px] px-5 py-3">
                  <p className="truncate text-[12.5px] font-medium text-ink">{report.title}</p>
                  <p className="truncate font-mono text-[10.5px] text-slate-400">{report.filename}</p>
                </td>
                <td className="px-4 py-3">
                  <Badge tone="bg-white/5 text-slate-600 border-line">
                    <Icon size={12} /> {report.format} · {humanSize(report.size)}
                  </Badge>
                </td>
                <td className="px-4 py-3">
                  <span
                    title={report.sha256}
                    className="inline-flex items-center gap-1 font-mono text-[10.5px] text-slate-400"
                  >
                    <ShieldCheck size={12} className="text-emerald-300" />
                    {report.sha256.slice(0, 12)}…
                  </span>
                </td>
                <td className="px-4 py-3 text-[11.5px] text-slate-500">{formatDate(report.created_at)}</td>
                <td className="px-4 py-3 text-[11.5px] text-slate-500">{relativeTime(report.expires_at)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1.5">
                    <a
                      href={report.preview_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex h-8 items-center gap-1 rounded-[7px] border border-line px-2.5 text-[11.5px] text-slate-600 transition hover:border-slate-400 hover:text-ink"
                    >
                      <ExternalLink size={12} /> Preview
                    </a>
                    <a
                      href={report.download_url}
                      className="inline-flex h-8 items-center gap-1 rounded-[7px] border border-line px-2.5 text-[11.5px] text-slate-600 transition hover:border-slate-400 hover:text-ink"
                    >
                      <Download size={12} /> Download
                    </a>
                    <button
                      type="button"
                      onClick={() => copyLink(report)}
                      className="inline-flex h-8 items-center gap-1 rounded-[7px] border border-line px-2.5 text-[11.5px] text-slate-600 transition hover:border-brand-ring/40 hover:text-brand-ring"
                    >
                      <Copy size={12} /> {copied === report.id ? "Copied" : "Signed link"}
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function ReportGenerator({
  scanId,
  onCreated,
  inline = false,
}: {
  scanId: string;
  onCreated?: (report: Report) => void;
  inline?: boolean;
}) {
  const [format, setFormat] = useState<ReportFormat>("html");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);

  async function generate() {
    setBusy(true);
    setNotice(null);
    try {
      const report = await api.post<Report>(`/api/scans/${scanId}/reports`, { format });
      onCreated?.(report);
      setNotice({ tone: "success", text: `${report.format.toUpperCase()} report generated · ${report.sha256.slice(0, 12)}…` });
    } catch (err) {
      setNotice({
        tone: "danger",
        text:
          err instanceof ApiError
            ? err.detail
            : "Could not generate the report",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={cn("space-y-3 px-5 py-4", inline ? "px-0 py-0" : "")}>
      <div className="flex flex-wrap gap-1.5">
        {formats.map(({ value, label, icon: Icon, hint }) => (
          <button
            key={value}
            type="button"
            title={hint}
            onClick={() => setFormat(value)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-[8px] border px-2.5 py-1.5 text-[11.5px] font-medium transition",
              format === value
                ? "border-brand-ring/40 bg-brand/15 text-brand-ring"
                : "border-line bg-panel text-slate-500 hover:text-ink",
            )}
          >
            <Icon size={13} /> {label}
          </button>
        ))}
        <Button size="sm" onClick={generate} disabled={busy} className="ml-auto">
          {busy ? <Loader2 size={13} className="animate-spin" /> : <FileText size={13} />}
          Generate report
        </Button>
      </div>
      {notice ? <Notice tone={notice.tone}>{notice.text}</Notice> : null}
    </div>
  );
}

export function useReports(scanId?: string) {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<Report[]>("/api/reports")
      .then((rows) => setReports(scanId ? rows.filter((row) => row.scan_id === scanId) : rows))
      .catch(() => setReports([]))
      .finally(() => setLoading(false));
  }, [scanId]);

  return { reports, setReports, loading };
}

export function ReportsCard({ scanId }: { scanId: string }) {
  const { reports, setReports } = useReports(scanId);
  return (
    <Card className="mt-4">
      <CardHeader
        title="Reports"
        subtitle="Canonical model rendered to JSON, Markdown, HTML or PDF. Downloads are SHA-256 verifiable and signed links expire."
        action={
          <span className="inline-flex items-center gap-1 text-[11.5px] text-slate-400">
            <ShieldCheck size={12} /> {reports.length} generated
          </span>
        }
      />
      <ReportGenerator scanId={scanId} onCreated={(report) => setReports((rows) => [report, ...rows])} />
      <div className="border-t border-line">
        <ReportTable reports={reports} empty="No report generated for this scan yet." />
      </div>
    </Card>
  );
}
