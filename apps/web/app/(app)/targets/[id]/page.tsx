"use client";

import {
  ArrowLeft,
  ArrowRight,
  Check,
  Copy,
  FileCheck2,
  Globe,
  Loader2,
  Play,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { ProfileBadge, StatusBadge } from "@/components/badges";
import { BurpImportCard } from "@/components/integrations";
import { ScanWizard } from "@/components/scan-wizard";
import { Button, Card, CardHeader, Modal, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { copyText } from "@/lib/clipboard";
import type { Scan, Target } from "@/lib/types";
import { cn, formatDate, relativeTime } from "@/lib/utils";

const methodLabels: Record<string, string> = {
  dns_txt: "DNS TXT record",
  well_known: "Well-known verification file",
  manual_attestation: "Manual attestation",
};

export default function TargetDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params.id;
  const [target, setTarget] = useState<Target | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [targetData, scanData] = await Promise.all([
        api.get<Target>(`/api/targets/${id}`),
        api.get<Scan[]>(`/api/scans?target_id=${id}`),
      ]);
      setTarget(targetData);
      setScans(scanData);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not load this target");
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  async function removeTarget() {
    setDeleting(true);
    try {
      await api.delete(`/api/targets/${id}`);
      router.replace("/targets");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not delete the target");
      setDeleting(false);
    }
  }

  if (error && !target) {
    return (
      <div>
        <Link href="/targets" className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-slate-500">
          <ArrowLeft size={14} /> Back to targets
        </Link>
        <Notice tone="danger">{error}</Notice>
      </div>
    );
  }

  if (!target) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-16 w-2/5" />
        <Skeleton className="h-[320px]" />
      </div>
    );
  }

  const verified = target.verification.verified;

  return (
    <div>
      <Link href="/targets" className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-slate-500 hover:text-ink">
        <ArrowLeft size={14} /> Back to targets
      </Link>

      <PageHeader
        eyebrow="Target"
        title={target.name}
        description={target.url}
        actions={
          <>
            <Button variant="secondary" onClick={() => setDeleteOpen(true)}>
              <Trash2 size={15} /> Delete
            </Button>
            <Button onClick={() => setScanOpen(true)} disabled={!verified}>
              <Play size={15} /> Start scan
            </Button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <VerificationPanel target={target} onUpdated={setTarget} />

          <Card>
            <CardHeader
              title="Scan history for this target"
              subtitle={`${scans.length} scan(s)`}
              action={
                verified ? (
                  <Button size="sm" variant="secondary" onClick={() => setScanOpen(true)}>
                    <Play size={13} /> New scan
                  </Button>
                ) : null
              }
            />
            {scans.length === 0 ? (
              <p className="px-5 py-10 text-center text-[13px] text-slate-400">
                No scans yet for this target.
              </p>
            ) : (
              <div className="divide-y divide-line">
                {scans.map((scan) => (
                  <Link
                    key={scan.id}
                    href={`/scans/${scan.id}`}
                    className="flex items-center justify-between gap-3 px-5 py-3.5 transition hover:bg-white/[0.05]"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <ProfileBadge profile={scan.profile} />
                      <StatusBadge status={scan.status} />
                      <span className="truncate text-[12.5px] text-slate-500">
                        {scan.findings_total} findings
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-3 text-[11.5px] text-slate-400">
                      {formatDate(scan.created_at)}
                      <ArrowRight size={14} />
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>

          <BurpImportCard targetId={target.id} onImported={() => void load()} />
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Target details" />
            <dl className="space-y-3 px-5 py-4 text-[12.5px]">
              <div>
                <dt className="text-slate-400">Host</dt>
                <dd className="mt-0.5 flex items-center gap-1.5 font-mono text-ink">
                  <Globe size={12} /> {target.host}
                </dd>
              </div>
              <div>
                <dt className="text-slate-400">Base URL</dt>
                <dd className="mt-0.5 break-all font-mono text-[11.5px] text-slate-600">{target.url}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Scope notes</dt>
                <dd className="mt-0.5 whitespace-pre-line leading-relaxed text-slate-600">
                  {target.scope_notes || "No scope notes recorded."}
                </dd>
              </div>
              <div className="grid grid-cols-2 gap-3 border-t border-line pt-3">
                <div>
                  <dt className="text-slate-400">Added</dt>
                  <dd className="mt-0.5 text-slate-600">{formatDate(target.created_at)}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Scans</dt>
                  <dd className="mt-0.5 tabular-nums text-slate-600">{target.scan_count}</dd>
                </div>
              </div>
            </dl>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-2 text-[12px] font-semibold text-ink">
              {verified ? (
                <ShieldCheck size={15} className="text-emerald-400" />
              ) : (
                <ShieldQuestion size={15} className="text-amber-400" />
              )}
              {verified ? "Authorization on file" : "Authorization pending"}
            </div>
            <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-500">
              {verified
                ? `Verified via ${methodLabels[target.verification.method ?? ""] ?? "record"}. Expires ${formatDate(
                    target.verification.expires_at,
                  )}. Re-verification keeps the audit trail current.`
                : "Scans stay blocked until one verification method succeeds. Every attempt is written to the audit log."}
            </p>
          </Card>
        </div>
      </div>

      <ScanWizard open={scanOpen} onClose={() => setScanOpen(false)} targets={[target]} initialTargetId={target.id} />

      <Modal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        title="Delete this target?"
        description="All scans, findings and authorization records for this target are removed permanently."
      >
        <div className="space-y-4">
          <Notice tone="danger">
            This action cannot be undone. {target.scan_count} scan(s) and their findings will be deleted.
          </Notice>
          {error ? <Notice tone="danger">{error}</Notice> : null}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setDeleteOpen(false)} disabled={deleting}>
              Keep target
            </Button>
            <Button variant="danger" onClick={removeTarget} disabled={deleting}>
              {deleting ? <Loader2 size={15} className="animate-spin" /> : <Trash2 size={15} />}
              Delete permanently
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

function VerificationPanel({ target, onUpdated }: { target: Target; onUpdated: (target: Target) => void }) {
  const [tab, setTab] = useState<"dns" | "file" | "attest">("dns");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [attestation, setAttestation] = useState("");
  const verification = target.verification;

  async function copy(value: string, key: string) {
    if (await copyText(value)) {
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } else {
      setError("Clipboard access was blocked by the browser");
    }
  }

  async function verify(kind: "dns" | "well-known" | "attest") {
    setBusy(kind);
    setError(null);
    try {
      const payload =
        kind === "attest" ? { accepted, attestation } : undefined;
      const updated = await api.post<Target>(`/api/targets/${target.id}/verify/${kind}`, payload);
      onUpdated(updated);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Verification failed");
    } finally {
      setBusy(null);
    }
  }

  if (verification.verified) {
    return (
      <Card className="overflow-hidden">
        <div className="flex items-start gap-3 border-b border-emerald-400/25 bg-emerald-500/10 px-5 py-4">
          <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-300">
            <ShieldCheck size={17} />
          </span>
          <div className="flex-1">
            <p className="text-[13.5px] font-semibold text-emerald-200">Target verified</p>
            <p className="mt-0.5 text-[12px] text-emerald-300/80">
              Method: {methodLabels[verification.method ?? ""] ?? verification.method} · Verified{" "}
              {formatDate(verification.verified_at)} · Expires {formatDate(verification.expires_at)}
            </p>
          </div>
          <span className="rounded-full border border-emerald-400/40 bg-panel px-2 py-0.5 text-[10.5px] font-medium text-emerald-300">
            90-day window
          </span>
        </div>
        <div className="grid gap-4 px-5 py-4 sm:grid-cols-2">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
              DNS record (kept for re-checks)
            </p>
            <p className="mt-1 font-mono text-[12px] text-ink">{verification.dns_record_name}</p>
            <p className="mt-0.5 break-all font-mono text-[11px] text-slate-500">
              TXT {verification.token}
            </p>
          </div>
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
              Verification file
            </p>
            <p className="mt-1 break-all font-mono text-[11px] text-slate-600">
              {verification.well_known_url}
            </p>
          </div>
          {error ? (
            <div className="sm:col-span-2">
              <Notice tone="warning">{error}</Notice>
            </div>
          ) : null}
          <div className="flex gap-2 sm:col-span-2">
            <Button size="sm" variant="secondary" onClick={() => verify("dns")} disabled={busy !== null}>
              {busy === "dns" ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
              Re-check DNS
            </Button>
            <Button size="sm" variant="secondary" onClick={() => verify("well-known")} disabled={busy !== null}>
              {busy === "well-known" ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <FileCheck2 size={13} />
              )}
              Re-check file
            </Button>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Verify ownership"
        subtitle="Choose one method. Verification is valid for 90 days and is logged."
      />
      <div className="border-b border-line px-5">
        <div className="flex gap-1">
          {(
            [
              ["dns", "DNS TXT record"],
              ["file", "Well-known file"],
              ["attest", "Manual attestation"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => {
                setTab(key);
                setError(null);
              }}
              className={cn(
                "-mb-px border-b-2 px-3 py-2.5 text-[12.5px] font-medium transition",
                tab === key
                  ? "border-brand text-brand-ring"
                  : "border-transparent text-slate-500 hover:text-ink",
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="space-y-4 px-5 py-4">
        {tab === "dns" ? (
          <>
            <p className="text-[12.5px] leading-relaxed text-slate-500">
              Add this TXT record in your DNS provider, wait for propagation, then check it.
            </p>
            <CopyRow
              label="Record name"
              value={verification.dns_record_name}
              copied={copied === "name"}
              onCopy={() => copy(verification.dns_record_name, "name")}
            />
            <CopyRow
              label="Record value (TXT)"
              value={verification.token}
              copied={copied === "value"}
              onCopy={() => copy(verification.token, "value")}
            />
            <Button onClick={() => verify("dns")} disabled={busy !== null}>
              {busy === "dns" ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />}
              Check DNS record
            </Button>
          </>
        ) : null}

        {tab === "file" ? (
          <>
            <p className="text-[12.5px] leading-relaxed text-slate-500">
              Serve a plain-text file at the URL below whose body contains the token.
            </p>
            <CopyRow
              label="File URL"
              value={verification.well_known_url}
              copied={copied === "url"}
              onCopy={() => copy(verification.well_known_url, "url")}
            />
            <CopyRow
              label="File content"
              value={verification.token}
              copied={copied === "token"}
              onCopy={() => copy(verification.token, "token")}
            />
            <Button onClick={() => verify("well-known")} disabled={busy !== null}>
              {busy === "well-known" ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <FileCheck2 size={15} />
              )}
              Fetch and check file
            </Button>
          </>
        ) : null}

        {tab === "attest" ? (
          <>
            <Notice tone="warning">{verification.attestation_required_text}</Notice>
            <label className="flex cursor-pointer items-start gap-2.5">
              <input
                type="checkbox"
                checked={accepted}
                onChange={(event) => setAccepted(event.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#1D4ED8]"
              />
              <span className="text-[12.5px] text-slate-600">I accept the authorization statement above.</span>
            </label>
            <div>
              <label className="label" htmlFor="attestation">
                Attestation note
              </label>
              <textarea
                id="attestation"
                className="field h-24 resize-none py-2"
                value={attestation}
                onChange={(event) => setAttestation(event.target.value)}
                placeholder="Authorized by (name, role) on 2026-11-15. Scope: staging web application."
              />
              <p className="mt-1 text-[11px] text-slate-400">Minimum 20 characters; stored in the audit trail.</p>
            </div>
            <Button
              onClick={() => verify("attest")}
              disabled={busy !== null || !accepted || attestation.trim().length < 20}
            >
              {busy === "attest" ? <Loader2 size={15} className="animate-spin" /> : <ShieldCheck size={15} />}
              Record attestation
            </Button>
          </>
        ) : null}

        {error ? <Notice tone="danger">{error}</Notice> : null}
        <p className="text-[11px] text-slate-400">
          Current token issued {relativeTime(target.created_at)}. Verification attempts appear in Activity.
        </p>
      </div>
    </Card>
  );
}

function CopyRow({
  label,
  value,
  copied,
  onCopy,
}: {
  label: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div>
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">{label}</p>
      <div className="flex items-center gap-2 rounded-[8px] border border-line bg-white/[0.04] px-3 py-2">
        <code className="min-w-0 flex-1 break-all font-mono text-[11.5px] text-ink">{value}</code>
        <button
          onClick={onCopy}
          className="shrink-0 rounded-[6px] p-1 text-slate-400 transition hover:bg-panel hover:text-ink"
          aria-label={`Copy ${label}`}
        >
          {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
        </button>
      </div>
    </div>
  );
}
