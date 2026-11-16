import * as React from "react";

import { cn } from "@/lib/utils";

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      {icon ? (
        <div className="flex h-11 w-11 items-center justify-center rounded-full bg-brand-soft text-brand-ring">
          {icon}
        </div>
      ) : null}
      <div>
        <p className="text-sm font-semibold text-ink">{title}</p>
        <p className="mx-auto mt-1 max-w-sm text-[13px] leading-relaxed text-slate-500">{description}</p>
      </div>
      {action}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-[8px] bg-slate-100", className)} />;
}

export function Notice({
  tone = "info",
  children,
}: {
  tone?: "info" | "warning" | "danger" | "success";
  children: React.ReactNode;
}) {
  const tones = {
    info: "border-brand-ring/25 bg-brand/10 text-brand-ring",
    warning: "border-amber-400/25 bg-amber-500/10 text-amber-300",
    danger: "border-red-400/25 bg-red-500/10 text-red-300",
    success: "border-emerald-400/25 bg-emerald-500/10 text-emerald-300",
  } as const;
  return (
    <div className={cn("rounded-[8px] border px-3.5 py-3 text-[13px] leading-relaxed", tones[tone])}>
      {children}
    </div>
  );
}
