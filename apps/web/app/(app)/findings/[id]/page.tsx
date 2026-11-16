"use client";

import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  ExternalLink,
  Fingerprint,
  Gauge,
  Info,
  Loader2,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { SeverityBadge, VerificationBadge } from "@/components/badges";
import { Button, Card, CardHeader, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { AiAnalysis, CheckInfo, Finding } from "@/lib/types";
import { cn, formatDate } from "@/lib/utils";

const categoryExplainer: Record<string, string> = {
  config: "Configuration findings describe defensive browser or server controls that are missing. They rarely break a site by themselves, but they remove layers that make other attacks harder.",
  session: "Session findings are about how cookies and tokens travel. Weak attributes make session theft easier once any script injection or network interception occurs.",
  transport: "Transport findings cover how traffic is protected in transit: TLS versions, certificates and HTTP-to-HTTPS behaviour.",
  disclosure: "Disclosure findings expose version numbers or internals. On their own they are low impact; combined with an unpatched component they shorten an attacker's path.",
};

export default function FindingDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [finding, setFinding] = useState<Finding | null>(null);
  const [check, setCheck] = useState<CheckInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"request" | "response">("request");
  const [analyses, setAnalyses] = useState<AiAnalysis[]>([]);
  const [aiBusy, setAiBusy] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Finding>(`/api/findings/${id}`)
      .then(setFinding)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load this finding"));
  }, [id]);

  useEffect(() => {
    api
      .get<AiAnalysis[]>(`/api/findings/${id}/ai`)
      .then(setAnalyses)
      .catch(() => setAnalyses([]));
  }, [id]);

  useEffect(() => {
    if (!finding) return;
    api
      .get<CheckInfo[]>("/api/checks")
      .then((catalog) => setCheck(catalog.find((item) => item.id === finding.check_id) ?? null))
      .catch(() => setCheck(null));
  }, [finding]);

  async function runAi(kind: "explanation" | "fp_review") {
    setAiBusy(kind);
    setAiError(null);
    try {
      const row = await api.post<AiAnalysis>(`/api/findings/${id}/ai/${kind}`);
      setAnalyses((current) => [row, ...current]);
      setFinding((current) => {
        if (!current) return current;
        if (kind === "explanation") {
          return { ...current, ai_summary: typeof row.payload.summary === "string" ? row.payload.summary : current.ai_summary };
        }
        const likelihood = row.payload.fp_likelihood;
        return {
          ...current,
          ai_false_positive_likelihood:
            typeof likelihood === "number" ? likelihood : current.ai_false_positive_likelihood,
        };
      });
    } catch (err) {
      setAiError(err instanceof ApiError ? err.detail : "Could not run the AI analyst");
    } finally {
      setAiBusy(null);
    }
  }

  if (error && !finding) {
    return (
      <div>
        <Link href="/findings" className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-slate-500">
          <ArrowLeft size={14} /> Back to findings
        </Link>
        <Notice tone="danger">{error}</Notice>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-20 w-3/5" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-[420px] lg:col-span-2" />
          <Skeleton className="h-[420px]" />
        </div>
      </div>
    );
  }

  const evidence = tab === "request" ? finding.request_evidence : finding.response_evidence;
  const explanation = analyses.find((item) => item.kind === "explanation");
  const fpReview = analyses.find((item) => item.kind === "fp_review");

  return (
    <div>
      <div className="mb-4 flex items-center gap-4 text-[12.5px] text-slate-500">
        <Link href="/findings" className="inline-flex items-center gap-1 hover:text-ink">
          <ArrowLeft size={14} /> Findings
        </Link>
        <span className="text-slate-300">/</span>
        <Link href={`/scans/${finding.scan_id}`} className="inline-flex items-center gap-1 hover:text-ink">
          Scan {finding.scan_id.slice(0, 8)} <ArrowRight size={12} />
        </Link>
      </div>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-3xl">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-brand-ring">
            {finding.category} · {finding.check_id}
          </p>
          <h1 className="text-[22px] font-semibold leading-snug tracking-tight text-ink">{finding.title}</h1>
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <VerificationBadge status={finding.verification_status} />
            <span className="inline-flex items-center gap-1 rounded-full border border-line bg-panel px-2 py-0.5 text-[11px] text-slate-500">
              <Fingerprint size={11} /> confidence {finding.confidence}/10
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-card border border-line bg-panel px-4 py-3 shadow-card">
          <Gauge size={18} className="text-brand-ring" />
          <div>
            <p className="text-[10.5px] font-semibold uppercase tracking-[0.08em] text-slate-400">Risk score</p>
            <p className="text-[22px] font-semibold leading-none tabular-nums text-ink">
              {finding.risk_score.toFixed(1)}
              <span className="text-[12px] font-normal text-slate-400"> / 10</span>
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Description" subtitle="What was observed and why it matters" />
            <div className="space-y-4 px-5 py-4 text-[13px] leading-relaxed text-slate-600">
              <p>{finding.description}</p>
              <div>
                <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                  Potential impact
                </p>
                <p>{finding.impact}</p>
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader title="Remediation" subtitle="Actionable fix, ordered by effort" />
            <div className="px-5 py-4 text-[13px] leading-relaxed text-slate-600">
              <p>{finding.remediation}</p>
              {finding.references.length > 0 ? (
                <div className="mt-4 border-t border-line pt-3">
                  <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                    References
                  </p>
                  <ul className="space-y-1">
                    {finding.references.map((reference) => (
                      <li key={reference}>
                        <a
                          href={reference}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="inline-flex items-center gap-1 break-all text-[12px] text-brand-ring hover:underline"
                        >
                          {reference} <ExternalLink size={11} className="shrink-0" />
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Evidence"
              subtitle="Raw material the finding is built on (secrets redacted)"
              action={
                <div className="flex rounded-[7px] border border-line bg-white/[0.04] p-0.5">
                  {(["request", "response"] as const).map((value) => (
                    <button
                      key={value}
                      onClick={() => setTab(value)}
                      className={cn(
                        "rounded-[6px] px-2.5 py-1 text-[11.5px] font-medium capitalize transition",
                        tab === value ? "bg-panel text-ink shadow-sm" : "text-slate-500",
                      )}
                    >
                      {value}
                    </button>
                  ))}
                </div>
              }
            />
            <div className="px-5 py-4">
              <pre className="code-block max-h-[360px] overflow-y-auto">
                {JSON.stringify(evidence, null, 2)}
              </pre>
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Affected asset" />
            <dl className="space-y-3 px-5 py-4 text-[12px]">
              <Meta label="URL" value={<span className="break-all font-mono text-[11.5px]">{finding.url}</span>} />
              <Meta label="Method" value={finding.method} />
              <Meta label="Parameter" value={finding.parameter ?? "—"} />
              <Meta label="Payload" value={finding.payload ?? "None (configuration finding)"} />
              <Meta label="Detected" value={formatDate(finding.created_at)} />
            </dl>
          </Card>

          <Card>
            <CardHeader title="Classification" />
            <dl className="space-y-3 px-5 py-4 text-[12px]">
              <Meta label="Category" value={finding.category} />
              <Meta label="Verification" value={finding.verification_status} />
              <Meta label="CVSS score" value={finding.cvss_score !== null ? finding.cvss_score.toFixed(1) : "Not assigned"} />
              <Meta label="CVSS vector" value={<span className="break-all font-mono text-[11px]">{finding.cvss_vector ?? "—"}</span>} />
              <div>
                <p className="mb-1 text-slate-400">CWE</p>
                <div className="flex flex-wrap gap-1">
                  {finding.cwe.length === 0 ? (
                    <span className="text-slate-500">—</span>
                  ) : (
                    finding.cwe.map((item) => (
                      <span key={item} className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10.5px] text-slate-600">
                        {item}
                      </span>
                    ))
                  )}
                </div>
              </div>
              <div>
                <p className="mb-1 text-slate-400">OWASP</p>
                <div className="flex flex-wrap gap-1">
                  {finding.owasp.length === 0 ? (
                    <span className="text-slate-500">—</span>
                  ) : (
                    finding.owasp.map((item) => (
                      <span key={item} className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10.5px] text-slate-600">
                        {item}
                      </span>
                    ))
                  )}
                </div>
              </div>
            </dl>
          </Card>

          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <Sparkles size={14} className="text-brand-ring" /> AI analyst
                </span>
              }
              action={
                <div className="flex gap-1.5">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => runAi("explanation")}
                    disabled={aiBusy !== null}
                  >
                    {aiBusy === "explanation" ? (
                      <Loader2 size={13} className="animate-spin" />
                    ) : (
                      <Sparkles size={13} />
                    )}
                    Explain
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => runAi("fp_review")}
                    disabled={aiBusy !== null}
                  >
                    {aiBusy === "fp_review" ? (
                      <Loader2 size={13} className="animate-spin" />
                    ) : (
                      <ShieldCheck size={13} />
                    )}
                    FP review
                  </Button>
                </div>
              }
            />
            <div className="space-y-3 px-5 py-4 text-[12px] leading-relaxed text-slate-600">
              {aiError ? <p className="text-red-400">{aiError}</p> : null}
              {explanation ? (
                <div className="space-y-2">
                  <p className="font-medium text-ink">{payloadText(explanation, "summary")}</p>
                  <p>{payloadText(explanation, "why_it_matters")}</p>
                  <AnalysisMeta analysis={explanation} />
                </div>
              ) : finding.ai_summary ? (
                <p>{finding.ai_summary}</p>
              ) : (
                <div className="flex items-start gap-2">
                  <Info size={14} className="mt-0.5 shrink-0 text-slate-400" />
                  <p className="text-slate-500">
                    Nothing generated yet. The analyst stays grounded in this finding&apos;s evidence and
                    falls back to deterministic text when no model provider is configured.
                  </p>
                </div>
              )}
              {fpReview ? (
                <div className="rounded-[8px] border border-line bg-white/[0.04] px-3 py-2.5">
                  <p className="mb-1 text-[11px] font-semibold text-ink">
                    False-positive likelihood: {Math.round(fpLikelihood(fpReview) * 100)}%
                  </p>
                  <p>{payloadText(fpReview, "reasoning")}</p>
                  <div className="mt-2">
                    <AnalysisMeta analysis={fpReview} />
                  </div>
                </div>
              ) : null}
            </div>
          </Card>

          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <BookOpen size={14} className="text-brand-ring" /> Learning mode
                </span>
              }
              subtitle="Plain-language context for students"
            />
            <div className="space-y-3 px-5 py-4 text-[12px] leading-relaxed text-slate-600">
              {check ? (
                <>
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                      What this check observes
                    </p>
                    <p>{check.learning.what}</p>
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                      Why it matters
                    </p>
                    <p>{check.learning.why}</p>
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                      Verify it yourself
                    </p>
                    <p>{check.learning.verify}</p>
                  </div>
                </>
              ) : (
                <p>
                  {categoryExplainer[finding.category] ??
                    "This finding belongs to a category the engine documents in its check catalogue."}
                </p>
              )}
              <div className="rounded-[8px] border border-line bg-white/[0.04] px-3 py-2.5">
                <p className="mb-1 flex items-center gap-1 text-[11px] font-semibold text-ink">
                  <ShieldCheck size={12} className="text-emerald-400" /> How confident are we?
                </p>
                <p className="text-slate-500">
                  {finding.verification_status === "verified"
                    ? "The condition was directly observed in a response fetched during this scan."
                    : "The condition is suspected and should be confirmed manually before reporting."}
                </p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function payloadText(analysis: AiAnalysis, key: string): string {
  const value = analysis.payload[key];
  return typeof value === "string" ? value : "";
}

function fpLikelihood(analysis: AiAnalysis): number {
  const value = analysis.payload.fp_likelihood;
  return typeof value === "number" ? value : 0;
}

function AnalysisMeta({ analysis }: { analysis: AiAnalysis }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[10.5px]">
      <span
        className={cn(
          "rounded-full border px-1.5 py-0.5",
          analysis.fallback
            ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
            : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
        )}
      >
        {analysis.fallback ? "deterministic fallback" : "model grounded"}
      </span>
      <span className="rounded-full border border-line bg-white/[0.04] px-1.5 py-0.5 text-slate-500">
        {analysis.provider} · {analysis.model} · {analysis.prompt_version}
      </span>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-slate-400">{label}</dt>
      <dd className="mt-0.5 break-words text-slate-700">{value}</dd>
    </div>
  );
}
