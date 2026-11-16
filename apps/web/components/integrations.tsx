"use client";

import { CheckCircle2, Plug, Upload, XCircle } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge, Button, Card, CardHeader, Notice } from "@/components/ui";
import { api, ApiError, ensureCsrf } from "@/lib/api";
import type { BurpImportResult, IntegrationStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

function Flag({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-medium",
        ok
          ? "border-emerald-400/25 bg-emerald-500/10 text-emerald-300"
          : "border-line bg-white/5 text-slate-400",
      )}
    >
      {ok ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
      {label}
    </span>
  );
}

export function IntegrationsCard() {
  const [status, setStatus] = useState<IntegrationStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<IntegrationStatus>("/api/integrations")
      .then(setStatus)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load integration status"));
  }, []);

  return (
    <Card className="mt-4">
      <CardHeader
        title="Integrations"
        subtitle="Operator-controlled external tools. Nuclei is disabled unless enabled and configured server-side; Burp exchanges and the upstream proxy are scoped by the same SSRF chokepoint as scans."
        action={<Plug size={15} className="text-slate-400" />}
      />
      {error ? (
        <div className="px-5 py-4">
          <Notice tone="danger">{error}</Notice>
        </div>
      ) : !status ? (
        <p className="px-5 py-6 text-[12px] text-slate-400">Loading integration status…</p>
      ) : (
        <div className="divide-y divide-line">
          <div className="flex flex-wrap items-center gap-2 px-5 py-3.5">
            <span className="w-[110px] text-[12.5px] font-medium text-ink">Nuclei</span>
            <Flag ok={status.nuclei.enabled} label={status.nuclei.enabled ? "enabled" : "disabled"} />
            <Flag ok={status.nuclei.configured} label="configured" />
            <Flag ok={status.nuclei.binary_present} label="binary present" />
            <Flag ok={status.nuclei.templates_present} label="templates" />
            <span className="ml-auto text-[11px] text-slate-400">
              {status.nuclei.severities.join(", ")} · {status.nuclei.rate_limit}/s · {status.nuclei.timeout}s
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2 px-5 py-3.5">
            <span className="w-[110px] text-[12.5px] font-medium text-ink">Burp Suite</span>
            <Flag ok={status.burp_import} label="XML/JSON import" />
            <Flag ok={status.burp_export} label="XML export" />
            <span className="ml-auto text-[11px] text-slate-400">
              Imports are rejected entirely when any URL is outside the target scope.
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2 px-5 py-3.5">
            <span className="w-[110px] text-[12.5px] font-medium text-ink">Upstream proxy</span>
            <Flag ok={status.upstream_proxy} label={status.upstream_proxy ? "configured" : "direct connection"} />
            <span className="ml-auto text-[11px] text-slate-400">
              http/https only · redirects still re-validated per hop
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2 px-5 py-3.5">
            <span className="w-[110px] text-[12.5px] font-medium text-ink">Plugin dirs</span>
            <Badge tone="bg-white/5 text-slate-600 border-line">
              {status.plugin_dirs.length ? status.plugin_dirs.join(", ") : "none configured"}
            </Badge>
          </div>
        </div>
      )}
    </Card>
  );
}

export function BurpImportCard({
  targetId,
  onImported,
}: {
  targetId: string;
  onImported?: (result: BurpImportResult) => void;
}) {
  const [format, setFormat] = useState<"xml" | "json">("xml");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);

  async function onFile(file: File | undefined) {
    if (!file) return;
    const text = await file.text();
    setBody(text);
    setFormat(file.name.toLowerCase().endsWith(".json") ? "json" : "xml");
  }

  async function submit() {
    setBusy(true);
    setNotice(null);
    try {
      const response = await fetch(`/api/targets/${targetId}/integrations/burp/import?format=${format}`, {
        method: "POST",
        credentials: "include",
        headers: {
          "x-csrf-token": await ensureCsrf(),
          "Content-Type": format === "xml" ? "application/xml" : "application/json",
        },
        body,
      });
      if (!response.ok) {
        let detail = "Import failed";
        try {
          const parsed = (await response.json()) as { detail?: string };
          if (parsed.detail) detail = parsed.detail;
        } catch {
          // non-JSON error body
        }
        throw new Error(detail);
      }
      const result = (await response.json()) as BurpImportResult;
      setNotice({
        tone: "success",
        text: `Imported ${result.imported} finding(s), skipped ${result.skipped}, out of scope ${result.out_of_scope}. No traffic was sent.`,
      });
      setBody("");
      onImported?.(result);
    } catch (err) {
      setNotice({ tone: "danger", text: err instanceof Error ? err.message : "Import failed" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-4">
      <CardHeader
        title="Import Burp Suite issues"
        subtitle="Paste a Burp XML/JSON export or choose a file (≤5 MB). Every URL is scope-checked; one out-of-scope URL rejects the whole import."
        action={<Upload size={15} className="text-slate-400" />}
      />
      <div className="space-y-3 px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          {(["xml", "json"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setFormat(value)}
              className={cn(
                "rounded-[7px] border px-2.5 py-1 text-[11.5px] font-medium uppercase transition",
                format === value
                  ? "border-brand-ring/40 bg-brand/15 text-brand-ring"
                  : "border-line bg-panel text-slate-500 hover:text-ink",
              )}
            >
              {value}
            </button>
          ))}
          <input
            type="file"
            accept=".xml,.json,application/xml,application/json"
            onChange={(event) => void onFile(event.target.files?.[0])}
            className="ml-auto text-[11.5px] text-slate-500 file:mr-2 file:rounded-[6px] file:border file:border-line file:bg-panel file:px-2 file:py-1 file:text-[11.5px] file:text-slate-600"
          />
        </div>
        <textarea
          value={body}
          onChange={(event) => setBody(event.target.value)}
          rows={4}
          placeholder={`Paste a Burp ${format.toUpperCase()} export here…`}
          className="w-full rounded-[8px] border border-line bg-[#0B0B0E] px-3 py-2 font-mono text-[11px] text-slate-600 outline-none focus:border-brand-ring/40"
        />
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] text-slate-400">{body.length.toLocaleString()} bytes pasted</span>
          <Button size="sm" onClick={submit} disabled={busy || body.trim().length === 0}>
            {busy ? "Importing…" : "Import as completed scan"}
          </Button>
        </div>
        {notice ? <Notice tone={notice.tone}>{notice.text}</Notice> : null}
      </div>
    </Card>
  );
}
