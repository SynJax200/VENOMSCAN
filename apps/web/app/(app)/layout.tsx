"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { AppShell } from "@/components/app-shell";
import { Brand } from "@/components/app-shell";
import { api } from "@/lib/api";
import type { User } from "@/lib/types";

export default function AppLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "anonymous">("loading");

  useEffect(() => {
    let mounted = true;
    api
      .get<User>("/api/auth/me")
      .then((me) => {
        if (!mounted) return;
        setUser(me);
        setState("ready");
      })
      .catch(() => {
        if (!mounted) return;
        setState("anonymous");
        router.replace("/login");
      });
    return () => {
      mounted = false;
    };
  }, [router]);

  if (state !== "ready" || !user) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-panel">
        <Brand />
        <p className="animate-pulse-soft text-[12.5px] text-slate-400">Restoring your session…</p>
      </div>
    );
  }

  return <AppShell user={user}>{children}</AppShell>;
}
