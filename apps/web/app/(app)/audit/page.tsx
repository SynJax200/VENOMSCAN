"use client";

import {
  Crosshair,
  ListChecks,
  Lock,
  LogIn,
  LogOut,
  Play,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserPlus,
  XCircle,
} from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { Card, EmptyState, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { AuditEvent } from "@/lib/types";
import { formatDate } from "@/lib/utils";

const actions: Record<string, { label: string; icon: React.ReactNode; tone: string }> = {
  "auth.login": { label: "Signed in", icon: <LogIn size={13} />, tone: "bg-blue-500/10 text-blue-300 border-blue-400/25" },
  "auth.login.failed": { label: "Sign-in failed", icon: <ShieldAlert size={13} />, tone: "bg-amber-500/10 text-amber-300 border-amber-400/25" },
  "auth.login.blocked": { label: "Sign-in throttled", icon: <Lock size={13} />, tone: "bg-red-500/10 text-red-300 border-red-400/25" },
  "auth.register": { label: "Account created", icon: <UserPlus size={13} />, tone: "bg-blue-500/10 text-blue-300 border-blue-400/25" },
  "auth.logout": { label: "Signed out", icon: <LogOut size={13} />, tone: "bg-slate-100 text-slate-600 border-slate-200" },
  "target.created": { label: "Target added", icon: <Crosshair size={13} />, tone: "bg-slate-100 text-slate-700 border-slate-200" },
  "target.verified": { label: "Authorization verified", icon: <ShieldCheck size={13} />, tone: "bg-emerald-500/10 text-emerald-300 border-emerald-400/25" },
  "target.deleted": { label: "Target deleted", icon: <Trash2 size={13} />, tone: "bg-red-500/10 text-red-300 border-red-400/25" },
  "scan.queued": { label: "Scan queued", icon: <Play size={13} />, tone: "bg-blue-500/10 text-blue-300 border-blue-400/25" },
  "scan.cancelled": { label: "Scan cancelled", icon: <XCircle size={13} />, tone: "bg-amber-500/10 text-amber-300 border-amber-400/25" },
};

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<AuditEvent[]>("/api/audit?limit=100")
      .then(setEvents)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Could not load activity"));
  }, []);

  return (
    <div>
      <PageHeader
        eyebrow="Transparency"
        title="Activity log"
        description="Append-only record of authorizations, scans and account events. Authorization events include the method used and when it expires."
      />

      {error ? <Notice tone="danger">{error}</Notice> : null}

      <Card>
        {!events ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-12" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <EmptyState
            icon={<ListChecks size={18} />}
            title="No activity recorded yet"
            description="Account, target and scan events will appear here as you work."
          />
        ) : (
          <ol className="divide-y divide-line">
            {events.map((event) => {
              const meta = actions[event.action] ?? {
                label: event.action,
                icon: <ListChecks size={13} />,
                tone: "bg-slate-100 text-slate-600 border-slate-200",
              };
              return (
                <li key={event.id} className="flex items-start gap-3 px-5 py-3.5">
                  <span className={`mt-0.5 flex h-6 items-center gap-1 rounded-full border px-2 text-[10.5px] font-medium ${meta.tone}`}>
                    {meta.icon}
                    {meta.label}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-[12.5px] text-slate-600">
                      {describe(event)}
                    </p>
                    <p className="mt-0.5 text-[10.5px] text-slate-400">
                      {event.target_type ? `${event.target_type} · ` : ""}
                      {event.target_id ? `${event.target_id.slice(0, 8)} · ` : ""}
                      {formatDate(event.created_at)}
                    </p>
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </Card>
    </div>
  );
}

function describe(event: AuditEvent): string {
  const detail = event.detail ?? {};
  const target = typeof detail.target === "string" ? detail.target : null;
  switch (event.action) {
    case "target.created":
      return target ?? "Target added to the workspace.";
    case "target.verified":
      return `Ownership verified via ${String(detail.method ?? "record")}${detail.expires_in_days ? `, valid ${detail.expires_in_days} days` : ""}.`;
    case "target.deleted":
      return target ? `Deleted ${target}.` : "Target deleted.";
    case "scan.queued":
      return `${target ?? "Target"} · profile ${String(detail.profile ?? "safe")}.`;
    case "scan.cancelled":
      return "Scan cancelled before completion.";
    default:
      return Object.keys(detail).length ? JSON.stringify(detail) : "—";
  }
}
