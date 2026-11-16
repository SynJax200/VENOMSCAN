"use client";

import {
  Crosshair,
  FileSearch,
  FileText,
  GraduationCap,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Settings2,
  ShieldAlert,
  X,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";

import { api, clearCsrfToken } from "@/lib/api";
import type { User } from "@/lib/types";
import { cn } from "@/lib/utils";

const navigation = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/targets", label: "Targets", icon: Crosshair },
  { href: "/scans", label: "Scans", icon: Radar },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/learning", label: "Learning", icon: GraduationCap },
  { href: "/audit", label: "Activity", icon: ScrollText },
  { href: "/settings", label: "Settings", icon: Settings2 },
];

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav className="flex flex-col gap-1">
      {navigation.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            href={href}
            onClick={onNavigate}
            className={cn(
              "group flex items-center gap-2.5 rounded-[8px] px-3 py-2 text-[13.5px] font-medium transition",
              active
                ? "nav-neon relative bg-white/[0.06] text-white"
                : "text-slate-500 hover:bg-white/5 hover:text-ink",
            )}
          >
            <Icon size={17} strokeWidth={active ? 2.2 : 1.8} />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <Image
        src="/brand/venomscan-logo-256.png"
        alt="VENOMSCAN emblem"
        width={36}
        height={36}
        priority
        className="h-9 w-9 shrink-0 select-none drop-shadow-[0_0_12px_rgba(47,180,224,0.28)]"
      />
      {!compact ? (
        <div className="leading-tight">
          <Image
            src="/brand/venomscan-wordmark.png"
            alt="VENOMSCAN"
            width={885}
            height={177}
            className="h-[21px] w-auto select-none"
          />
          <p className="mt-1 text-[9.5px] font-medium uppercase tracking-[0.16em] text-slate-400">
            Cyber Mind Space
          </p>
        </div>
      ) : null}
    </div>
  );
}

export function AppShell({ user, children }: { user: User; children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [drawer, setDrawer] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

  async function signOut() {
    setSigningOut(true);
    try {
      await api.post("/api/auth/logout");
    } catch {
      // session may already be gone; clear local state regardless
    }
    clearCsrfToken();
    router.replace("/login");
  }

  const initials = (user.name || user.email)
    .split(/[\s@.]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");

  return (
    <div className="relative min-h-screen bg-surface">
      <div className="app-aurora" aria-hidden />
      <div className="neon-grid" aria-hidden />
      <div className="neon-scanline" aria-hidden />
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[248px] flex-col border-r border-line bg-[#0C0C0F]/95 px-4 py-5 backdrop-blur lg:flex">
        <div className="px-1">
          <Brand />
        </div>
        <div className="mt-8">
          <p className="mb-2 px-3 text-[10.5px] font-semibold uppercase tracking-[0.12em] text-slate-400">
            Workspace
          </p>
          <NavLinks />
        </div>
        <div className="mt-auto space-y-3">
          <div className="rounded-[9px] border border-line bg-panel p-3">
            <div className="flex items-center gap-1.5 text-[11.5px] font-semibold text-ink">
              <FileSearch size={13} className="text-brand-ring" />
              Authorized testing only
            </div>
            <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">
              Every target must be verified before a scan can start. Active checks always require explicit consent.
            </p>
          </div>
          <div className="flex items-center gap-2.5 rounded-[9px] border border-line bg-panel px-3 py-2.5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-soft text-[11px] font-semibold text-brand-ring">
              {initials || "VS"}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[12.5px] font-medium text-ink">{user.name || "Analyst"}</p>
              <p className="truncate text-[11px] text-slate-400">{user.email}</p>
            </div>
            <button
              onClick={signOut}
              disabled={signingOut}
              aria-label="Sign out"
              className="rounded-[6px] p-1.5 text-slate-400 transition hover:bg-white/[0.04] hover:text-ink"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-line bg-surface/85 px-4 backdrop-blur lg:hidden">
        <Brand compact />
        <div className="flex items-center gap-2">
          <span className="max-w-[150px] truncate text-[12px] text-slate-500">{user.email}</span>
          <button
            onClick={() => setDrawer(true)}
            aria-label="Open navigation"
            className="rounded-[7px] border border-line p-2 text-slate-600"
          >
            <Menu size={17} />
          </button>
        </div>
      </header>

      {drawer ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-[2px]" onClick={() => setDrawer(false)} />
          <div className="absolute inset-y-0 left-0 flex w-[270px] flex-col bg-[#0C0C0F] px-4 py-5 shadow-pop">
            <div className="flex items-center justify-between">
              <Brand />
              <button
                onClick={() => setDrawer(false)}
                aria-label="Close navigation"
                className="rounded-[6px] p-1 text-slate-500"
              >
                <X size={18} />
              </button>
            </div>
            <div className="mt-8">
              <NavLinks onNavigate={() => setDrawer(false)} />
            </div>
            <button
              onClick={signOut}
              className="mt-auto flex items-center gap-2 rounded-[8px] px-3 py-2 text-[13px] font-medium text-slate-500"
            >
              <LogOut size={16} /> Sign out
            </button>
          </div>
        </div>
      ) : null}

      <main className="relative z-10 px-4 py-6 sm:px-6 lg:ml-[248px] lg:px-10 lg:py-8">
        <div key={pathname} className="page-enter mx-auto w-full max-w-[1180px]">
          {children}
        </div>
      </main>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow ? (
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-brand-ring">{eyebrow}</p>
        ) : null}
        <h1 className="neon-title text-[22px] font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 max-w-2xl text-[13.5px] text-slate-500">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
