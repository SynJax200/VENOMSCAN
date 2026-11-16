"use client";

import { Loader2, Play, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Button, Modal, Notice } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { Scan, ScanProfile, Target, WorkspaceSettings } from "@/lib/types";
import { cn } from "@/lib/utils";

const profiles: { value: ScanProfile; title: string; description: string; tag: string }[] = [
  {
    value: "passive",
    title: "Passive",
    description: "Root fetch, fingerprinting and configuration checks. No payloads.",
    tag: "Lowest footprint",
  },
  {
    value: "safe",
    title: "Safe",
    description: "Passive checks plus non-destructive validation. Recommended default.",
    tag: "Recommended",
  },
  {
    value: "active",
    title: "Active",
    description:
      "Read-only canary probes: reflected XSS, SQL error, template evaluation and path traversal. Requires explicit consent per scan.",
    tag: "Opt-in only",
  },
];

export function ScanWizard({
  open,
  onClose,
  targets,
  initialTargetId,
}: {
  open: boolean;
  onClose: () => void;
  targets: Target[];
  initialTargetId?: string;
}) {
  const router = useRouter();
  const verified = targets.filter((target) => target.verification.verified);
  const [targetId, setTargetId] = useState(initialTargetId ?? verified[0]?.id ?? "");
  const [profile, setProfile] = useState<ScanProfile>("safe");
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let mounted = true;
    api
      .get<WorkspaceSettings>("/api/settings")
      .then((settings) => {
        if (mounted) setProfile(settings.scan_defaults.profile);
      })
      .catch(() => undefined);
    return () => {
      mounted = false;
    };
  }, [open]);

  const selected = targets.find((target) => target.id === targetId);

  async function start() {
    if (!targetId) {
      setError("Choose a verified target first.");
      return;
    }
    if (profile === "active" && !consent) {
      setError("Active scans require explicit consent.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const scan = await api.post<Scan>("/api/scans", {
        target_id: targetId,
        profile,
        active_consent: profile === "active" ? consent : false,
      });
      onClose();
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not start the scan");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Start a new assessment"
      description="Pick a verified target and a scan profile."
      width="max-w-xl"
    >
      {verified.length === 0 ? (
        <Notice tone="warning">
          No verified targets yet. Add a target and complete DNS, file or attestation verification
          before scanning.
        </Notice>
      ) : (
        <div className="space-y-5">
          <div>
            <label className="label" htmlFor="scan-target">
              Target
            </label>
            <select
              id="scan-target"
              className="field"
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
            >
              {verified.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} — {target.host}
                </option>
              ))}
            </select>
          </div>

          <div>
            <p className="label">Scan profile</p>
            <div className="grid gap-2">
              {profiles.map((option) => {
                const active = profile === option.value;
                return (
                  <button
                    type="button"
                    key={option.value}
                    onClick={() => setProfile(option.value)}
                    className={cn(
                      "rounded-[9px] border px-3.5 py-3 text-left transition",
                      active
                        ? "border-brand bg-brand-soft/60 ring-2 ring-brand-ring/40"
                        : "border-line bg-panel hover:border-slate-300",
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[13.5px] font-semibold text-ink">{option.title}</span>
                      <span className="rounded-full border border-line bg-panel px-2 py-0.5 text-[10.5px] font-medium text-slate-500">
                        {option.tag}
                      </span>
                    </div>
                    <p className="mt-1 text-[12px] leading-relaxed text-slate-500">{option.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {profile === "active" ? (
            <div className="space-y-2.5">
              <label className="flex cursor-pointer items-start gap-2.5 rounded-[8px] border border-orange-400/25 bg-orange-500/10 px-3.5 py-3">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(event) => setConsent(event.target.checked)}
                  className="mt-0.5 h-4 w-4 accent-orange-600"
                />
                <span className="text-[12px] leading-relaxed text-orange-200">
                  <ShieldAlert size={13} className="mr-1 inline" />
                  I explicitly authorize controlled active validation against this target for this
                  scan.
                </span>
              </label>
              <p className="rounded-[8px] border border-line bg-white/[0.03] px-3.5 py-2.5 text-[11.5px] leading-relaxed text-slate-500">
                Active probes stay read-only and capped: at most 4 XSS canaries, 4 SQL error quotes,
                3 template expressions and 2 traversal checks on GET parameters. Every request still
                passes the scope allowlist, SSRF guard, rate limit and per-scan request budget.
                File contents are never stored in evidence.
              </p>
            </div>
          ) : null}

          {selected ? (
            <p className="text-[11.5px] leading-relaxed text-slate-400">
              Scope is locked to <span className="font-medium text-slate-600">{selected.host}</span>. The
              engine re-validates every request and rejects anything outside scope or resolving to
              private/metadata addresses.
            </p>
          ) : null}

          {error ? <Notice tone="danger">{error}</Notice> : null}

          <div className="flex justify-end gap-2 border-t border-line pt-4">
            <Button variant="secondary" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={start} disabled={busy || verified.length === 0}>
              {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
              Start scan
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}
