"use client";

import { BrainCircuit, KeyRound, Loader2, PlugZap, Plus, Save, SlidersHorizontal, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { SeverityBadge } from "@/components/badges";
import { IntegrationsCard } from "@/components/integrations";
import { Button, Card, CardHeader, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type {
  AiProviderTest,
  AiSettings,
  CheckInfo,
  Credential,
  ScanProfile,
  Target,
  User,
  WorkspaceSettings,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const profiles: { value: ScanProfile; title: string; description: string }[] = [
  {
    value: "passive",
    title: "Passive",
    description: "Configuration checks only. No probing requests beyond the root fetch.",
  },
  {
    value: "safe",
    title: "Safe",
    description: "Adds bounded, non-destructive probes: CORS, exposed files, secrets, redirects.",
  },
  {
    value: "active",
    title: "Active",
    description: "Read-only canary probes. Still requires explicit per-scan consent.",
  },
];

export default function SettingsPage() {
  const [checks, setChecks] = useState<CheckInfo[] | null>(null);
  const [profile, setProfile] = useState<ScanProfile>("safe");
  const [disabled, setDisabled] = useState<string[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [user, setUser] = useState<User | null>(null);
  const [accountForm, setAccountForm] = useState({
    target_id: "",
    label: "",
    role: "user",
    identity: "",
    headerName: "Authorization",
    headerValue: "",
  });
  const [addingAccount, setAddingAccount] = useState(false);
  const [accountNotice, setAccountNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(
    null,
  );
  const [ai, setAi] = useState<AiSettings | null>(null);
  const [aiForm, setAiForm] = useState({
    provider: "openai_compat",
    model: "gpt-4o-mini",
    base_url: "",
    api_key: "",
  });
  const [savingAi, setSavingAi] = useState(false);
  const [testingAi, setTestingAi] = useState(false);
  const [aiNotice, setAiNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [catalog, settings, accounts, me, targetRows] = await Promise.all([
          api.get<CheckInfo[]>("/api/checks"),
          api.get<WorkspaceSettings>("/api/settings"),
          api.get<Credential[]>("/api/settings/credentials"),
          api.get<User>("/api/auth/me"),
          api.get<Target[]>("/api/targets"),
        ]);
        setChecks(catalog);
        setProfile(settings.scan_defaults.profile);
        setDisabled(settings.disabled_checks);
        setCredentials(accounts);
        setTargets(targetRows);
        setUser(me);
        setAccountForm((current) => ({
          ...current,
          target_id: current.target_id || targetRows[0]?.id || "",
        }));
        if (me.role === "admin") {
          const aiSettings = await api.get<AiSettings>("/api/settings/ai");
          setAi(aiSettings);
          setAiForm({
            provider: aiSettings.provider,
            model: aiSettings.model,
            base_url: aiSettings.base_url,
            api_key: "",
          });
        }
      } catch (err) {
        setNotice({
          tone: "danger",
          text: err instanceof ApiError ? err.detail : "Could not load workspace settings",
        });
      } finally {
        setLoading(false);
      }
    }
    void load();
  }, []);

  const isAdmin = user?.role === "admin";

  const groups = useMemo(() => {
    const map = new Map<string, CheckInfo[]>();
    for (const check of checks ?? []) {
      map.set(check.category, [...(map.get(check.category) ?? []), check]);
    }
    return [...map.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [checks]);

  const enabled = (checks?.length ?? 0) - disabled.length;

  function toggle(id: string) {
    setDirty(true);
    setNotice(null);
    setDisabled((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  }

  async function save() {
    setSaving(true);
    setNotice(null);
    try {
      const updated = await api.put<WorkspaceSettings>("/api/settings", {
        scan_defaults: { profile },
        disabled_checks: disabled,
      });
      setProfile(updated.scan_defaults.profile);
      setDisabled(updated.disabled_checks);
      setDirty(false);
      setNotice({ tone: "success", text: "Settings saved. The next scan uses these defaults." });
    } catch (err) {
      setNotice({
        tone: "danger",
        text: err instanceof ApiError ? err.detail : "Could not save settings",
      });
    } finally {
      setSaving(false);
    }
  }

  async function addAccount() {
    setAddingAccount(true);
    setAccountNotice(null);
    try {
      const created = await api.post<Credential>("/api/settings/credentials", {
        target_id: accountForm.target_id,
        label: accountForm.label,
        role: accountForm.role,
        identity: accountForm.identity,
        headers: { [accountForm.headerName]: accountForm.headerValue },
      });
      setCredentials((current) => [...current, created]);
      setAccountForm({
        target_id: accountForm.target_id,
        label: "",
        role: "user",
        identity: "",
        headerName: "Authorization",
        headerValue: "",
      });
      setAccountNotice({
        tone: "success",
        text: "Test account stored encrypted and scoped to that target. Only active scans of the same target can use it.",
      });
    } catch (err) {
      setAccountNotice({
        tone: "danger",
        text: err instanceof ApiError ? err.detail : "Could not store the test account",
      });
    } finally {
      setAddingAccount(false);
    }
  }

  async function removeAccount(id: string) {
    setAccountNotice(null);
    try {
      await api.delete<void>(`/api/settings/credentials/${id}`);
      setCredentials((current) => current.filter((item) => item.id !== id));
    } catch (err) {
      setAccountNotice({
        tone: "danger",
        text: err instanceof ApiError ? err.detail : "Could not delete the test account",
      });
    }
  }

  async function saveAi(clearKey = false) {
    setSavingAi(true);
    setAiNotice(null);
    try {
      const updated = await api.put<AiSettings>("/api/settings/ai", {
        provider: aiForm.provider,
        model: aiForm.model,
        base_url: aiForm.base_url,
        ...(clearKey ? { api_key: "" } : aiForm.api_key ? { api_key: aiForm.api_key } : {}),
      });
      setAi(updated);
      setAiForm((current) => ({ ...current, api_key: "" }));
      setAiNotice({
        tone: "success",
        text: "AI settings saved. Analyses run on the configured provider, or on the deterministic fallback when it is unavailable.",
      });
    } catch (err) {
      setAiNotice({
        tone: "danger",
        text: err instanceof ApiError ? err.detail : "Could not save AI settings",
      });
    } finally {
      setSavingAi(false);
    }
  }

  async function testAi() {
    setTestingAi(true);
    setAiNotice(null);
    try {
      const result = await api.post<AiProviderTest>("/api/settings/ai/test");
      if (!result.configured) {
        setAiNotice({
          tone: "danger",
          text: "No provider is configured. Save a provider and key to exercise the model path; analyses stay on the deterministic fallback.",
        });
      } else if (result.reachable) {
        setAiNotice({
          tone: "success",
          text: `${result.provider} · ${result.model} answered in ${result.latency_ms} ms. Structured output and grounding checks are active.`,
        });
      } else {
        setAiNotice({
          tone: "danger",
          text: `Provider test failed: ${result.error || "no structured answer"}. Analyses will fall back deterministically.`,
        });
      }
    } catch (err) {
      setAiNotice({
        tone: "danger",
        text: err instanceof ApiError ? err.detail : "Could not reach the provider test endpoint",
      });
    } finally {
      setTestingAi(false);
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Settings"
        title="Scan defaults and modules"
        description="Defaults apply when a scan does not choose a profile. Disabled checks are removed from the engine registry for every scan from this workspace."
        actions={
          <Button onClick={save} disabled={saving || !dirty || loading || !isAdmin}>
            {saving ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />}
            Save changes
          </Button>
        }
      />

      {notice ? (
        <div className="mb-4">
          <Notice tone={notice.tone}>{notice.text}</Notice>
        </div>
      ) : null}

      {!loading && !isAdmin ? (
        <div className="mb-4">
          <Notice tone="danger">
            Workspace defaults and AI provider settings are administrator-only. Target-scoped
            test accounts remain available below.
          </Notice>
        </div>
      ) : null}

      {loading ? (
        <div className="space-y-4">
          <Skeleton className="h-[190px]" />
          <Skeleton className="h-[360px]" />
        </div>
      ) : (
        <div className="space-y-4">
          <Card>
            <CardHeader
              title="Default scan profile"
              subtitle="Pre-selected in the scan wizard. Authorization and consent rules still apply."
            />
            <div className="grid gap-2 px-5 py-4 sm:grid-cols-3">
              {profiles.map((option) => {
                const active = profile === option.value;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => {
                      setProfile(option.value);
                      setDirty(true);
                      setNotice(null);
                    }}
                    className={cn(
                      "rounded-[9px] border px-3.5 py-3 text-left transition",
                      active
                        ? "border-brand bg-brand-soft/60 ring-2 ring-brand-ring/40"
                        : "border-line bg-panel hover:border-slate-300",
                    )}
                  >
                    <span className="text-[13.5px] font-semibold text-ink">{option.title}</span>
                    <p className="mt-1 text-[12px] leading-relaxed text-slate-500">
                      {option.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </Card>

          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <SlidersHorizontal size={14} className="text-brand-ring" /> Check modules
                </span>
              }
              subtitle={`${enabled} of ${checks?.length ?? 0} checks enabled`}
            />
            <div className="divide-y divide-line">
              {groups.map(([category, items]) => (
                <div key={category} className="px-5 py-4">
                  <p className="mb-2 text-[10.5px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                    {category}
                  </p>
                  <div className="space-y-1">
                    {items.map((check) => {
                      const on = !disabled.includes(check.id);
                      return (
                        <label
                          key={check.id}
                          className="flex cursor-pointer items-start gap-3 rounded-[8px] px-2 py-2 transition hover:bg-white/[0.03]"
                        >
                          <input
                            type="checkbox"
                            checked={on}
                            onChange={() => toggle(check.id)}
                            className="mt-0.5 h-4 w-4 accent-[#0078A7]"
                          />
                          <span className="min-w-0 flex-1">
                            <span className="flex flex-wrap items-center gap-2">
                              <span className="text-[13px] font-medium text-ink">{check.name}</span>
                              <span className="font-mono text-[10.5px] text-slate-400">
                                {check.id}
                              </span>
                              <SeverityBadge severity={check.severity} />
                              <span className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
                                {check.profile}
                              </span>
                            </span>
                            <span className="mt-0.5 block text-[12px] leading-relaxed text-slate-500">
                              {check.learning.what}
                            </span>
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <KeyRound size={14} className="text-brand-ring" /> Test accounts
                </span>
              }
              subtitle="Encrypted credentials used only by the IDOR and authorization checks in active scans"
            />
            <div className="space-y-4 px-5 py-4">
              {credentials.length === 0 ? (
                <p className="text-[12px] text-slate-500">
                  No test accounts yet. Add two accounts you control to enable object- and
                  function-level authorization checks.
                </p>
              ) : (
                <div className="space-y-2">
                  {credentials.map((account) => (
                    <div
                      key={account.id}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-[9px] border border-line bg-panel px-3 py-2.5"
                    >
                      <div className="min-w-0">
                        <p className="text-[13px] font-medium text-ink">
                          {account.label}{" "}
                          <span className="rounded-full border border-line bg-white/[0.04] px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
                            {account.role}
                          </span>
                        </p>
                        <p className="mt-0.5 truncate font-mono text-[11px] text-slate-400">
                          {account.identity || "no identity marker"} ·{" "}
                          {account.header_names.join(", ")} ·{" "}
                          {targets.find((target) => target.id === account.target_id)?.name ??
                            "unscoped legacy row"}
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        onClick={() => removeAccount(account.id)}
                        aria-label={`Delete ${account.label}`}
                      >
                        <Trash2 size={14} />
                      </Button>
                    </div>
                  ))}
                </div>
              )}

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="sm:col-span-2">
                  <label className="label" htmlFor="account-target">
                    Target
                  </label>
                  <select
                    id="account-target"
                    className="field"
                    value={accountForm.target_id}
                    onChange={(event) =>
                      setAccountForm({ ...accountForm, target_id: event.target.value })
                    }
                  >
                    {targets.length === 0 ? <option value="">Add a target first</option> : null}
                    {targets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name} · {target.url}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="label" htmlFor="account-label">
                    Label
                  </label>
                  <input
                    id="account-label"
                    className="field"
                    value={accountForm.label}
                    onChange={(event) =>
                      setAccountForm({ ...accountForm, label: event.target.value })
                    }
                    placeholder="alice"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="account-role">
                    Role
                  </label>
                  <select
                    id="account-role"
                    className="field"
                    value={accountForm.role}
                    onChange={(event) =>
                      setAccountForm({ ...accountForm, role: event.target.value })
                    }
                  >
                    {["user", "viewer", "analyst", "student", "admin", "other"].map((role) => (
                      <option key={role} value={role}>
                        {role}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="sm:col-span-2">
                  <label className="label" htmlFor="account-identity">
                    Identity marker in responses (email or username)
                  </label>
                  <input
                    id="account-identity"
                    className="field"
                    value={accountForm.identity}
                    onChange={(event) =>
                      setAccountForm({ ...accountForm, identity: event.target.value })
                    }
                    placeholder="alice@demo.test"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="account-header">
                    Header name
                  </label>
                  <input
                    id="account-header"
                    className="field font-mono"
                    value={accountForm.headerName}
                    onChange={(event) =>
                      setAccountForm({ ...accountForm, headerName: event.target.value })
                    }
                    placeholder="Authorization"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="account-header-value">
                    Header value
                  </label>
                  <input
                    id="account-header-value"
                    className="field font-mono"
                    type="password"
                    value={accountForm.headerValue}
                    onChange={(event) =>
                      setAccountForm({ ...accountForm, headerValue: event.target.value })
                    }
                    placeholder="Bearer …"
                    autoComplete="off"
                  />
                </div>
              </div>

              {accountNotice ? <Notice tone={accountNotice.tone}>{accountNotice.text}</Notice> : null}

              <div className="flex items-center justify-between gap-3">
                <p className="text-[11px] leading-relaxed text-slate-400">
                  Values are Fernet-encrypted at rest and never returned by the API. They are
                  decrypted only inside the worker that runs an active scan.
                </p>
                <Button
                  onClick={addAccount}
                  disabled={
                    addingAccount ||
                    credentials.length >= 3 ||
                    !accountForm.target_id ||
                    accountForm.label.trim().length < 2 ||
                    accountForm.headerValue.trim().length === 0
                  }
                >
                  {addingAccount ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
                  Add account
                </Button>
              </div>
            </div>
          </Card>

          {isAdmin ? (
          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <BrainCircuit size={15} className="text-brand-ring" /> AI intelligence
                </span>
              }
              subtitle="Optional model provider. Every feature keeps working without one via the deterministic fallback."
              action={
                <span
                  className={cn(
                    "rounded-full border px-2 py-0.5 text-[10.5px] font-medium",
                    ai?.key_configured
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                      : "border-line bg-white/[0.04] text-slate-400",
                  )}
                >
                  {ai?.key_configured ? "Key configured" : ai?.provider === "ollama" ? "Local, no key" : "No key — fallback only"}
                </span>
              }
            />
            <div className="space-y-4 px-5 py-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="ai-provider">
                    Provider
                  </label>
                  <select
                    id="ai-provider"
                    className="field"
                    value={aiForm.provider}
                    onChange={(event) => setAiForm({ ...aiForm, provider: event.target.value })}
                  >
                    <option value="openai_compat">OpenAI-compatible</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="ollama">Ollama (local)</option>
                  </select>
                </div>
                <div>
                  <label className="label" htmlFor="ai-model">
                    Model
                  </label>
                  <input
                    id="ai-model"
                    className="field font-mono"
                    value={aiForm.model}
                    onChange={(event) => setAiForm({ ...aiForm, model: event.target.value })}
                    placeholder="gpt-4o-mini"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="label" htmlFor="ai-base-url">
                    Base URL (blank uses the provider default)
                  </label>
                  <input
                    id="ai-base-url"
                    className="field font-mono"
                    value={aiForm.base_url}
                    onChange={(event) => setAiForm({ ...aiForm, base_url: event.target.value })}
                    placeholder={
                      aiForm.provider === "ollama"
                        ? "http://127.0.0.1:11434"
                        : aiForm.provider === "anthropic"
                          ? "https://api.anthropic.com"
                          : "https://api.openai.com/v1"
                    }
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="label" htmlFor="ai-api-key">
                    API key {ai?.key_configured ? "(a key is stored; leave blank to keep it)" : "(write-only)"}
                  </label>
                  <input
                    id="ai-api-key"
                    className="field font-mono"
                    type="password"
                    value={aiForm.api_key}
                    onChange={(event) => setAiForm({ ...aiForm, api_key: event.target.value })}
                    placeholder={ai?.key_configured ? "••••••••" : "sk-…"}
                    autoComplete="off"
                  />
                </div>
              </div>

              {aiNotice ? <Notice tone={aiNotice.tone}>{aiNotice.text}</Notice> : null}

              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="max-w-xl text-[11px] leading-relaxed text-slate-400">
                  Keys are Fernet-encrypted at rest. Scan facts are fenced as untrusted data in the
                  prompt, and model output is rejected when it cites URLs, CVEs or evidence refs the
                  scan never observed. Ambient failures degrade to deterministic text.
                </p>
                <div className="flex items-center gap-2">
                  {ai?.key_configured ? (
                    <Button variant="ghost" onClick={() => saveAi(true)} disabled={savingAi}>
                      Remove key
                    </Button>
                  ) : null}
                  <Button variant="ghost" onClick={testAi} disabled={testingAi || savingAi}>
                    {testingAi ? <Loader2 size={15} className="animate-spin" /> : <PlugZap size={15} />}
                    Test provider
                  </Button>
                  <Button onClick={() => saveAi()} disabled={savingAi || aiForm.model.trim().length === 0}>
                    {savingAi ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />}
                    Save AI settings
                  </Button>
                </div>
              </div>
            </div>
          </Card>
          ) : null}

          <IntegrationsCard />

          <p className="text-[11.5px] leading-relaxed text-slate-400">
            Disabling a module only suppresses its findings. Every request still passes through the
            scope allowlist, SSRF guard, rate limit and request budget.
          </p>
        </div>
      )}
    </div>
  );
}
