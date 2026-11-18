"use client";

import { ArrowRight, CheckCircle2, Loader2, Lock } from "lucide-react";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Brand } from "@/components/app-shell";
import { Button, Notice } from "@/components/ui";
import { api, ApiError, ensureCsrf, setCsrfToken } from "@/lib/api";
import type { AuthResponse, User } from "@/lib/types";
import { cn } from "@/lib/utils";

type Mode = "login" | "register";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .get<User>("/api/auth/me")
      .then(() => router.replace("/dashboard"))
      .catch(() => undefined);
  }, [router]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await ensureCsrf();
      const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const payload = mode === "login" ? { email, password } : { email, password, name };
      const auth = await api.post<AuthResponse>(path, payload, false);
      setCsrfToken(auth.csrf_token);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Something went wrong. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen bg-surface">
      <section className="relative hidden w-[48%] flex-col justify-between overflow-hidden bg-[#070709] px-12 py-10 text-white lg:flex">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.14]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(47,180,224,0.35) 1px, transparent 1px), linear-gradient(90deg, rgba(47,180,224,0.35) 1px, transparent 1px)",
            backgroundSize: "52px 52px",
            maskImage: "radial-gradient(circle at 30% 20%, black, transparent 75%)",
          }}
        />
        <div
          aria-hidden
          className="pointer-events-none absolute -right-28 top-[12%] h-[420px] w-[420px] rounded-full bg-brand/30 blur-[120px]"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute -left-24 bottom-[16%] h-[360px] w-[360px] rounded-full bg-accent/25 blur-[120px]"
        />

        <div className="relative flex items-center gap-3">
          <Image
            src="/brand/venomscan-logo-512.png"
            alt="S&S Researcher emblem"
            width={512}
            height={338}
            priority
            className="h-[52px] w-auto select-none drop-shadow-[0_0_22px_rgba(47,180,224,0.32)]"
          />
          <div className="leading-tight">
            <span className="wordmark-metal block text-[27px] font-semibold leading-none tracking-[0.18em]">
              VENOMSCAN
            </span>
            <p className="brand-company mt-1 text-[10px] font-semibold tracking-[0.16em]">
              S&amp;S Researcher
            </p>
          </div>
        </div>

        <div className="relative max-w-lg">
          <p className="text-[11px] font-semibold uppercase tracking-[0.35em] text-slate-400">
            A calmer tomorrow
          </p>
          <h1 className="mt-5">
            <span className="wordmark-metal block text-5xl font-semibold leading-none tracking-[0.14em] sm:text-6xl">
              VENOMSCAN
            </span>
          </h1>
          <p className="mt-6 text-[12px] font-semibold uppercase tracking-[0.28em] text-slate-400">
            Where security meets intelligence
          </p>
          <p className="mt-4 max-w-md text-[13.5px] leading-relaxed text-slate-500">
            Reconnaissance, evidence-based findings and plain-language remediation in one
            workspace — scoped to what you have verified you own.
          </p>
          <ul className="mt-8 space-y-3">
            {[
              "Every finding is tied to evidence collected from the target",
              "Scope enforcement, SSRF protection and safe defaults in the engine",
              "Live scan telemetry with a full audit trail",
            ].map((line, index) => (
              <li key={line} className="flex items-start gap-2.5 text-[13px] text-slate-600">
                <CheckCircle2
                  size={15}
                  className={cn("mt-0.5 shrink-0", index === 1 ? "text-accent" : "text-brand-ring")}
                />
                {line}
              </li>
            ))}
          </ul>
        </div>

        <p className="relative max-w-sm text-[11.5px] leading-relaxed text-slate-500">
          VENOMSCAN never scans a target without verified authorization. Active payload checks are
          opt-in and blocked on unverified targets.
        </p>
      </section>

      <section className="relative flex flex-1 items-center justify-center px-5 py-10">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accent/60 to-transparent lg:hidden"
        />
        <div className="w-full max-w-[400px]">
          <div className="mb-8 lg:hidden">
            <Brand />
          </div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-brand-ring">
            Workspace access
          </p>
          <h2 className="mt-1.5 text-[24px] font-semibold tracking-tight text-ink">
            {mode === "login" ? "Sign in to VENOMSCAN" : "Create your analyst account"}
          </h2>
          <p className="mt-1.5 text-[13.5px] text-slate-500">
            {mode === "login"
              ? "Continue to your assessments, findings and reports."
              : "One verified workspace for your authorized security testing."}
          </p>

          <div className="mt-6 inline-flex rounded-[9px] border border-line bg-white/[0.04] p-1">
            {(["login", "register"] as Mode[]).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => {
                  setMode(value);
                  setError(null);
                }}
                className={cn(
                  "rounded-[7px] px-3.5 py-1.5 text-[12.5px] font-medium transition",
                  mode === value
                    ? "bg-white/10 text-white shadow-sm"
                    : "text-slate-500 hover:text-ink",
                )}
              >
                {value === "login" ? "Sign in" : "Create account"}
              </button>
            ))}
          </div>

          <form onSubmit={submit} className="mt-6 space-y-4">
            {mode === "register" ? (
              <div>
                <label className="label" htmlFor="name">
                  Full name
                </label>
                <input
                  id="name"
                  className="field"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Aarav Sharma"
                  autoComplete="name"
                />
              </div>
            ) : null}
            <div>
              <label className="label" htmlFor="email">
                Work email
              </label>
              <input
                id="email"
                className="field"
                type="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@company.com"
                autoComplete="email"
              />
            </div>
            <div>
              <label className="label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                className="field"
                type="password"
                required
                minLength={10}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder={mode === "register" ? "At least 10 characters" : "Your password"}
                autoComplete={mode === "login" ? "current-password" : "new-password"}
              />
            </div>

            {error ? <Notice tone="danger">{error}</Notice> : null}

            <Button type="submit" disabled={busy} className="w-full">
              {busy ? <Loader2 size={16} className="animate-spin" /> : null}
              {mode === "login" ? "Sign in" : "Create account"}
              {!busy ? <ArrowRight size={16} /> : null}
            </Button>
          </form>

          <div className="mt-6 flex items-start gap-2 rounded-[8px] border border-line bg-white/[0.03] px-3.5 py-3 text-[12px] leading-relaxed text-slate-500">
            <Lock size={14} className="mt-0.5 shrink-0 text-slate-400" />
            Sessions use httpOnly cookies with CSRF protection. Password hashing is scrypt
            (memory-hard) and never leaves the server.
          </div>
        </div>
      </section>
    </div>
  );
}
