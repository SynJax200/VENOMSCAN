"use client";

import {
  ArrowRight,
  Crosshair,
  Globe,
  Loader2,
  Plus,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { ScanWizard } from "@/components/scan-wizard";
import { Button, Card, EmptyState, Modal, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { Target } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export default function TargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [initialTarget, setInitialTarget] = useState<string | undefined>(undefined);

  async function load() {
    try {
      setTargets(await api.get<Target[]>("/api/targets"));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not load targets");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  function openScan(targetId?: string) {
    setInitialTarget(targetId);
    setScanOpen(true);
  }

  return (
    <div>
      <PageHeader
        eyebrow="Attack surface"
        title="Authorized targets"
        description="Every target needs verified authorization before a scan is allowed. DNS, well-known file and attestation methods are all audited."
        actions={
          <Button onClick={() => setAddOpen(true)}>
            <Plus size={16} /> Add target
          </Button>
        }
      />

      {error ? <Notice tone="danger">{error}</Notice> : null}

      {!targets && !error ? (
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-[184px]" />
          ))}
        </div>
      ) : null}

      {targets && targets.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Crosshair size={18} />}
            title="No targets yet"
            description="Add the web application you own or are authorized to test. You will receive a DNS record and verification file to prove control."
            action={<Button size="sm" onClick={() => setAddOpen(true)}>Add your first target</Button>}
          />
        </Card>
      ) : null}

      {targets && targets.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2">
          {targets.map((target) => (
            <Card key={target.id} className="flex flex-col p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="truncate text-[14.5px] font-semibold text-ink">{target.name}</h3>
                    {target.verification.verified ? (
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-400/25 bg-emerald-500/10 px-2 py-0.5 text-[10.5px] font-medium text-emerald-300">
                        <ShieldCheck size={11} /> Verified
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/25 bg-amber-500/10 px-2 py-0.5 text-[10.5px] font-medium text-amber-300">
                        <ShieldQuestion size={11} /> Unverified
                      </span>
                    )}
                  </div>
                  <p className="mt-1 flex items-center gap-1.5 text-[12px] text-slate-500">
                    <Globe size={12} /> {target.host}
                  </p>
                </div>
                <span className="shrink-0 rounded-[7px] bg-white/[0.04] px-2 py-1 text-[11px] font-medium tabular-nums text-slate-500">
                  {target.scan_count} scans
                </span>
              </div>

              <p className="mt-3 truncate font-mono text-[11.5px] text-slate-400">{target.url}</p>
              {target.scope_notes ? (
                <p className="mt-2 line-clamp-2 text-[12px] leading-relaxed text-slate-500">
                  {target.scope_notes}
                </p>
              ) : null}

              <div className="mt-auto flex items-center justify-between gap-2 border-t border-line pt-3.5">
                <span className="text-[11px] text-slate-400">Added {formatDate(target.created_at)}</span>
                <div className="flex items-center gap-2">
                  <Link href={`/targets/${target.id}`}>
                    <Button variant="ghost" size="sm">
                      Manage <ArrowRight size={13} />
                    </Button>
                  </Link>
                  <Button
                    size="sm"
                    variant={target.verification.verified ? "primary" : "secondary"}
                    disabled={!target.verification.verified}
                    title={target.verification.verified ? "Start a scan" : "Verify ownership first"}
                    onClick={() => openScan(target.id)}
                  >
                    Scan
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : null}

      <AddTargetModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={(target) => {
          setAddOpen(false);
          router.push(`/targets/${target.id}`);
        }}
      />

      <ScanWizard
        open={scanOpen}
        onClose={() => setScanOpen(false)}
        targets={targets ?? []}
        initialTargetId={initialTarget}
      />
    </div>
  );
}

function AddTargetModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (target: Target) => void;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [scopeNotes, setScopeNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await api.post<Target>("/api/targets", {
        name,
        url,
        scope_notes: scopeNotes,
      });
      setName("");
      setUrl("");
      setScopeNotes("");
      onCreated(created);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not add the target");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add an authorized target"
      description="Only add systems you own or have written permission to test."
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="target-name">
            Display name
          </label>
          <input
            id="target-name"
            className="field"
            required
            minLength={2}
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Customer portal (staging)"
          />
        </div>
        <div>
          <label className="label" htmlFor="target-url">
            Target URL
          </label>
          <input
            id="target-url"
            className="field font-mono text-[13px]"
            required
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://staging.example.com"
          />
          <p className="mt-1.5 text-[11.5px] text-slate-400">
            Use the base URL you control. Scanning is restricted to this host.
          </p>
        </div>
        <div>
          <label className="label" htmlFor="target-scope">
            Scope notes
          </label>
          <textarea
            id="target-scope"
            className="field h-20 resize-none py-2"
            value={scopeNotes}
            onChange={(event) => setScopeNotes(event.target.value)}
            placeholder="Authorized by: … · Environment: staging · Exclusions: /billing"
          />
        </div>
        {error ? <Notice tone="danger">{error}</Notice> : null}
        <div className="flex justify-end gap-2 border-t border-line pt-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
            Add target
          </Button>
        </div>
      </form>
    </Modal>
  );
}
