"use client";

import {
  ArrowLeft,
  AtSign,
  BadgeCheck,
  Ban,
  CheckCircle2,
  CircleDashed,
  Clock,
  Crosshair,
  FileCode2,
  FileJson,
  Globe,
  GraduationCap,
  History,
  Layers,
  Loader2,
  Network,
  Play,
  Radar,
  Send,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Waypoints,
} from "lucide-react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { ProfileBadge, SeverityBadge, StatusBadge, VerificationBadge } from "@/components/badges";
import { ScanExtras } from "@/components/scan-extras";
import { Button, Card, CardHeader, Notice, Progress, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type {
  AiAnalysis,
  ApiIntel,
  AssistantAnswer,
  Endpoint,
  EndpointIntel,
  EndpointState,
  JsIntel,
  Recon,
  Scan,
  ScanDetail,
  ScanEndpointLearning,
  ScanEvent,
  SurfaceHints,
} from "@/lib/types";
import { cn, formatDate, phaseLabels, relativeTime } from "@/lib/utils";

const phases = [
  "authorizing",
  "recon",
  "crawling",
  "analyzing",
  "verifying",
  "correlating",
  "reporting",
];

const terminalStatuses = new Set(["completed", "failed", "cancelled"]);

const SurfaceGraph = dynamic(
  () => import("@/components/surface-graph").then((module) => module.SurfaceGraph),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[430px] items-center justify-center text-[12px] text-slate-400">
        Loading surface graph…
      </div>
    ),
  },
);

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params.id;
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [stream, setStream] = useState<"connecting" | "live" | "polling" | "closed">("connecting");
  const [cancelling, setCancelling] = useState(false);
  const [endpointSource, setEndpointSource] = useState("all");
  const [endpointState, setEndpointState] = useState<"all" | EndpointState>("all");
  const [endpointLearning, setEndpointLearning] = useState<ScanEndpointLearning | null>(null);
  const [learningOpen, setLearningOpen] = useState(false);
  const [learningBusy, setLearningBusy] = useState(false);
  const [learningError, setLearningError] = useState<string | null>(null);
  const [aiAnalyses, setAiAnalyses] = useState<AiAnalysis[]>([]);
  const [aiBusy, setAiBusy] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [chat, setChat] = useState<{ question: string; answer: AssistantAnswer }[]>([]);
  const pollRef = useRef<number | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const refresh = useCallback(async () => {
    const detail = await api.get<ScanDetail>(`/api/scans/${id}`);
    setScan(detail);
    return detail;
  }, [id]);

  const startPolling = useCallback(() => {
    if (pollRef.current) return;
    setStream("polling");
    pollRef.current = window.setInterval(async () => {
      try {
        const detail = await refresh();
        if (terminalStatuses.has(detail.status)) {
          stopPolling();
          setStream("closed");
        }
      } catch {
        // keep polling; transient network blips should not kill the view
      }
    }, 2500);
  }, [refresh, stopPolling]);

  const connectStream = useCallback(
    async (afterId: number) => {
      sourceRef.current?.close();
      const source = new EventSource(`/api/scans/${id}/events/stream?after=${afterId}`);
      sourceRef.current = source;
      source.onopen = () => setStream("live");
      source.addEventListener("scan_event", (event) => {
        const parsed = JSON.parse((event as MessageEvent).data) as ScanEvent;
        setEvents((prev) =>
          prev.some((item) => item.id === parsed.id) ? prev : [...prev, parsed].slice(-500),
        );
        setScan((prev) =>
          prev
            ? {
                ...prev,
                progress: Math.max(prev.progress, parsed.progress),
                phase: parsed.phase,
                status: prev.status === "queued" ? "running" : prev.status,
              }
            : prev,
        );
      });
      source.addEventListener("stream_end", async () => {
        source.close();
        sourceRef.current = null;
        setStream("closed");
        try {
          await refresh();
        } catch {
          // ignore; the page already has the latest events
        }
      });
      source.onerror = () => {
        source.close();
        sourceRef.current = null;
        startPolling();
      };
    },
    [id, refresh, startPolling],
  );

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const [detail, history] = await Promise.all([
          api.get<ScanDetail>(`/api/scans/${id}`),
          api.get<ScanEvent[]>(`/api/scans/${id}/events`),
        ]);
        if (!active) return;
        setScan(detail);
        setEvents(history);
        if (terminalStatuses.has(detail.status)) {
          setStream("closed");
          return;
        }
        const lastId = history.length ? history[history.length - 1].id : 0;
        await connectStream(lastId);
      } catch (err) {
        if (!active) return;
        setError(err instanceof ApiError ? err.detail : "Could not load this scan");
      }
    })();
    return () => {
      active = false;
      sourceRef.current?.close();
      sourceRef.current = null;
      stopPolling();
    };
  }, [connectStream, id, stopPolling]);

  useEffect(() => {
    api
      .get<AiAnalysis[]>(`/api/scans/${id}/ai`)
      .then(setAiAnalyses)
      .catch(() => setAiAnalyses([]));
  }, [id]);

  async function runScanAi(kind: string) {
    setAiBusy(kind);
    setAiError(null);
    try {
      const row = await api.post<AiAnalysis>(`/api/scans/${id}/ai/${kind}`);
      setAiAnalyses((current) => [row, ...current]);
    } catch (err) {
      setAiError(err instanceof ApiError ? err.detail : "Could not run the AI analyst");
    } finally {
      setAiBusy(null);
    }
  }

  async function toggleEndpointLearning() {
    if (learningOpen) {
      setLearningOpen(false);
      return;
    }
    setLearningOpen(true);
    if (endpointLearning) return;
    setLearningBusy(true);
    setLearningError(null);
    try {
      setEndpointLearning(await api.get<ScanEndpointLearning>(`/api/learning/scans/${id}/endpoints`));
    } catch (err) {
      setLearningError(err instanceof ApiError ? err.detail : "Could not load endpoint lessons");
    } finally {
      setLearningBusy(false);
    }
  }

  async function ask() {
    if (!scan) return;
    setAsking(true);
    setAiError(null);
    try {
      const answer = await api.post<AssistantAnswer>("/api/assistant", {
        scan_id: scan.id,
        question,
      });
      setChat((current) => [...current, { question, answer }]);
      setQuestion("");
    } catch (err) {
      setAiError(err instanceof ApiError ? err.detail : "Could not reach the assistant");
    } finally {
      setAsking(false);
    }
  }

  async function cancelScan() {
    if (!scan) return;
    setCancelling(true);
    try {
      const updated = await api.post<Scan>(`/api/scans/${id}/cancel`);
      setScan((prev) => (prev ? { ...prev, ...updated } : prev));
      setStream("closed");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not cancel the scan");
    } finally {
      setCancelling(false);
    }
  }

  async function rescan() {
    if (!scan) return;
    try {
      const created = await api.post<Scan>("/api/scans", {
        target_id: scan.target_id,
        profile: scan.profile,
        active_consent: scan.profile === "active",
      });
      router.push(`/scans/${created.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not start a new scan");
    }
  }

  if (error && !scan) {
    return (
      <div>
        <Link href="/scans" className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-slate-500">
          <ArrowLeft size={14} /> Back to scans
        </Link>
        <Notice tone="danger">{error}</Notice>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-16 w-2/5" />
        <Skeleton className="h-[220px]" />
        <Skeleton className="h-[320px]" />
      </div>
    );
  }

  const active = !terminalStatuses.has(scan.status);
  const currentPhase = phases.indexOf(scan.phase);
  const recon: Recon = scan.recon ?? {};
  const dnsEntries = Object.entries(recon.dns?.records ?? {});
  const crawl = recon.crawl ?? {};
  const dirs = recon.dirs;
  const surfaceHints: SurfaceHints = recon.surface ?? {};
  const tls = recon.tls ?? {};
  const robots = recon.robots ?? {};
  const waf = recon.waf ?? {};
  const ipIntel = recon.ip_intel ?? {};
  const subdomains = recon.subdomains ?? {};
  const whois = recon.whois ?? {};
  const history = recon.history ?? {};
  const exposure = recon.exposure ?? [];
  const neighbours = recon.neighbours ?? {};
  const jsIntel: JsIntel = recon.js_intel ?? {};
  const endpointIntel: EndpointIntel = recon.endpoint_intel ?? {
    cluster_count: 0,
    endpoint_count: 0,
    templated: 0,
    api_clusters: 0,
    clusters: [],
  };
  const endpointClusters = (endpointIntel.clusters ?? []).slice(0, 25);
  const apiSurface = recon.api ?? {};
  const apiDocuments = apiSurface.documents ?? [];
  const apiIntel: ApiIntel = recon.api_intel ?? {};
  const apiTokens = apiIntel.jwt?.tokens ?? [];
  const apiGraphql = apiIntel.graphql;
  const apiHasIntel =
    (apiIntel.spec?.documents ?? 0) > 0 || apiTokens.length > 0 || (apiGraphql?.probed ?? 0) > 0;
  const verification = recon.verification ?? {};
  const verificationTotal =
    (verification.verified ?? 0) + (verification.suspected ?? 0) + (verification.rejected ?? 0);
  const endpointSources = Array.from(new Set(scan.endpoints.map((endpoint) => endpoint.source))).sort();
  const endpointSurfaceState = (endpoint: Endpoint): EndpointState =>
    endpoint.state ?? (endpoint.status_code === null ? "unverified" : "live");
  const liveEndpointCount = scan.endpoints.filter(
    (endpoint) => endpointSurfaceState(endpoint) === "live",
  ).length;
  const unverifiedEndpointCount = scan.endpoints.length - liveEndpointCount;
  const latestAi = (kind: string) => aiAnalyses.find((item) => item.kind === kind);
  const aiSummary = latestAi("summary");
  const aiPrioritize = latestAi("prioritize");
  const aiSurface = latestAi("surface_summary");
  const aiCorrelate = latestAi("correlate");
  const aiEndpoints = latestAi("endpoint_prioritize");
  const aiNextSteps = latestAi("next_steps");
  const aiJs = latestAi("js_analysis");
  const aiApi = latestAi("api_analysis");
  const visibleEndpoints = scan.endpoints.filter(
    (endpoint) =>
      (endpointSource === "all" || endpoint.source === endpointSource) &&
      (endpointState === "all" || endpointSurfaceState(endpoint) === endpointState),
  );

  return (
    <div>
      <Link href="/scans" className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-slate-500 hover:text-ink">
        <ArrowLeft size={14} /> Back to scans
      </Link>

      <PageHeader
        eyebrow="Live assessment"
        title={scan.target_name}
        description={scan.target_url}
        actions={
          <>
            <ProfileBadge profile={scan.profile} />
            <StatusBadge status={scan.status} />
            {active ? (
              <Button
                variant="secondary"
                onClick={cancelScan}
                disabled={cancelling}
                title="Kill switch: stops outbound traffic within ~2 seconds"
              >
                {cancelling ? <Loader2 size={15} className="animate-spin" /> : <Ban size={15} />}
                {cancelling ? "Stopping…" : "Cancel"}
              </Button>
            ) : (
              <Button onClick={rescan}>
                <Play size={15} /> Re-scan
              </Button>
            )}
          </>
        }
      />

      {error ? (
        <div className="mb-4">
          <Notice tone="danger">{error}</Notice>
        </div>
      ) : null}

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4">
          <div className="flex items-center gap-2 text-[12.5px]">
            <span
              className={cn(
                "flex h-2 w-2 rounded-full",
                stream === "live" ? "animate-pulse-soft bg-emerald-500" : "bg-slate-300",
              )}
            />
            <span className="font-medium text-ink">
              {active ? phaseLabels[scan.phase] ?? scan.phase : "Finished"}
            </span>
            <span className="text-slate-400">
              {stream === "live"
                ? "· live events"
                : stream === "polling"
                  ? "· reconnecting (polling)"
                  : active
                    ? "· connecting"
                    : "· stream closed"}
            </span>
          </div>
          <span className="text-[12px] tabular-nums text-slate-500">{scan.progress}%</span>
        </div>
        <div className="px-5 pb-4 pt-2.5">
          <Progress
            value={scan.progress}
            tone={
              scan.status === "failed"
                ? "bg-severity-critical"
                : scan.status === "cancelled"
                  ? "bg-slate-400"
                  : scan.status === "completed"
                    ? "bg-emerald-500"
                    : "bg-brand"
            }
          />
        </div>

        <div className="grid grid-cols-2 divide-x divide-line border-y border-line sm:grid-cols-4">
          <StatPill
            icon={<Terminal size={14} />}
            label="Requests"
            value={
              scan.stats.max_requests
                ? `${scan.stats.requests ?? 0} / ${scan.stats.max_requests}`
                : (scan.stats.requests ?? 0)
            }
          />
          <StatPill icon={<Layers size={14} />} label="Endpoints" value={scan.stats.endpoints ?? 0} />
          <StatPill icon={<Server size={14} />} label="Technologies" value={scan.stats.technologies ?? 0} />
          <StatPill icon={<ShieldAlert size={14} />} label="Findings" value={scan.findings_total} />
        </div>

        <div className="flex flex-wrap gap-1.5 px-5 py-3">
          {phases.map((phase, index) => {
            const done = scan.status === "completed" || index < currentPhase;
            const current = phase === scan.phase && scan.status !== "completed";
            return (
              <span
                key={phase}
                className={cn(
                  "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10.5px] font-medium",
                  done
                    ? "border-emerald-400/25 bg-emerald-500/10 text-emerald-300"
                    : current
                      ? "border-blue-400/25 bg-blue-500/10 text-blue-300"
                      : "border-line bg-panel text-slate-400",
                )}
              >
                {done ? <CheckCircle2 size={11} /> : <CircleDashed size={11} />}
                {phaseLabels[phase] ?? phase}
              </span>
            );
          })}
        </div>

        {scan.summary ? (
          <div className="flex items-start gap-2.5 border-t border-line bg-white/[0.03] px-5 py-3.5">
            <Sparkles size={15} className="mt-0.5 shrink-0 text-brand-ring" />
            <p className="text-[12.5px] leading-relaxed text-slate-600">{scan.summary}</p>
          </div>
        ) : null}
        {scan.error ? (
          <div className="border-t border-line px-5 py-3.5">
            <Notice tone="danger">{scan.error}</Notice>
          </div>
        ) : null}
      </Card>

      <Card className="mt-4">
        <CardHeader
          title={
            <span className="flex items-center gap-1.5">
              <Sparkles size={15} className="text-brand-ring" /> AI intelligence
            </span>
          }
          subtitle="Grounded in this scan's recorded evidence. Runs on the deterministic fallback when no model provider is configured."
          action={
            <div className="flex flex-wrap justify-end gap-1.5">
              <Button size="sm" variant="secondary" onClick={() => runScanAi("summary")} disabled={aiBusy !== null}>
                {aiBusy === "summary" ? <Loader2 size={13} className="animate-spin" /> : <FileCode2 size={13} />}
                Executive summary
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("prioritize")} disabled={aiBusy !== null}>
                {aiBusy === "prioritize" ? <Loader2 size={13} className="animate-spin" /> : <Layers size={13} />}
                Prioritize
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("surface_summary")} disabled={aiBusy !== null}>
                {aiBusy === "surface_summary" ? <Loader2 size={13} className="animate-spin" /> : <Network size={13} />}
                Surface
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("correlate")} disabled={aiBusy !== null}>
                {aiBusy === "correlate" ? <Loader2 size={13} className="animate-spin" /> : <Waypoints size={13} />}
                Correlate
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("endpoint_prioritize")} disabled={aiBusy !== null}>
                {aiBusy === "endpoint_prioritize" ? <Loader2 size={13} className="animate-spin" /> : <Crosshair size={13} />}
                Endpoints
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("next_steps")} disabled={aiBusy !== null}>
                {aiBusy === "next_steps" ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
                Next steps
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("js_analysis")} disabled={aiBusy !== null}>
                {aiBusy === "js_analysis" ? <Loader2 size={13} className="animate-spin" /> : <Terminal size={13} />}
                JS intel
              </Button>
              <Button size="sm" variant="secondary" onClick={() => runScanAi("api_analysis")} disabled={aiBusy !== null}>
                {aiBusy === "api_analysis" ? <Loader2 size={13} className="animate-spin" /> : <Server size={13} />}
                API intel
              </Button>
            </div>
          }
        />
        <div className="grid gap-4 px-5 py-4 lg:grid-cols-2">
          <AiBlock title="Executive summary" analysis={aiSummary} empty="Generate a stakeholder-ready summary of this scan.">
            {aiSummary ? (
              <div className="space-y-2">
                <p className="font-medium text-ink">{aiText(aiSummary, "headline")}</p>
                <p>{aiText(aiSummary, "summary")}</p>
                <ul className="list-disc space-y-1 pl-4">
                  {aiList(aiSummary, "priorities").slice(0, 5).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </AiBlock>

          <AiBlock title="Remediation order" analysis={aiPrioritize} empty="Rank findings by practical remediation priority.">
            {aiPrioritize ? (
              <ol className="space-y-1.5">
                {aiOrder(aiPrioritize).slice(0, 5).map((item, index) => (
                  <li key={`${item.finding_id}-${index}`} className="flex gap-2">
                    <span className="font-semibold tabular-nums text-slate-400">{index + 1}.</span>
                    <span>
                      <span className="font-medium text-ink">{item.title}</span>
                      {item.reason ? <span className="text-slate-500"> - {item.reason}</span> : null}
                    </span>
                  </li>
                ))}
              </ol>
            ) : null}
          </AiBlock>

          <AiBlock title="Attack-surface summary" analysis={aiSurface} empty="Cluster discovered endpoints by purpose.">
            {aiSurface ? (
              <div className="space-y-2">
                <p>{aiText(aiSurface, "summary")}</p>
                <div className="flex flex-wrap gap-1.5">
                  {aiList(aiSurface, "clusters").map((item) => (
                    <span key={item} className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10.5px] text-slate-500">
                      {item}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </AiBlock>

          <AiBlock title="Cross-finding themes" analysis={aiCorrelate} empty="Look for shared root causes across findings.">
            {aiCorrelate ? (
              <div className="space-y-2">
                <p>{aiText(aiCorrelate, "summary")}</p>
                <div className="flex flex-wrap gap-1.5">
                  {aiList(aiCorrelate, "themes").map((item) => (
                    <span key={item} className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10.5px] text-slate-500">
                      {item}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </AiBlock>

          <AiBlock title="Endpoint review order" analysis={aiEndpoints} empty="Rank endpoints for manual review.">
            {aiEndpoints ? (
              <div className="space-y-2">
                <p>{aiText(aiEndpoints, "summary")}</p>
                <ol className="space-y-1.5">
                  {aiObjects(aiEndpoints, "order").slice(0, 8).map((item, index) => (
                    <li key={`${String(item.url)}-${index}`} className="flex gap-2">
                      <span className="font-semibold tabular-nums text-slate-400">{index + 1}.</span>
                      <span>
                        <span className="font-medium text-ink">
                          {String(item.method ?? "GET")} {String(item.url ?? "")}
                        </span>
                        {item.reason ? <span className="text-slate-500"> - {String(item.reason)}</span> : null}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            ) : null}
          </AiBlock>

          <AiBlock title="Next steps" analysis={aiNextSteps} empty="Plan the owner's remediation sequence.">
            {aiNextSteps ? (
              <div className="space-y-2">
                <p>{aiText(aiNextSteps, "summary")}</p>
                <ol className="space-y-1.5">
                  {aiObjects(aiNextSteps, "steps").slice(0, 6).map((item, index) => (
                    <li key={`${String(item.title)}-${index}`}>
                      <span className="font-medium text-ink">
                        {index + 1}. {String(item.title ?? "")}
                      </span>
                      {item.detail ? <p className="text-slate-500">{String(item.detail)}</p> : null}
                    </li>
                  ))}
                </ol>
              </div>
            ) : null}
          </AiBlock>

          <AiBlock title="JavaScript intelligence" analysis={aiJs} empty="Inspect JavaScript-derived routes and exposures.">
            {aiJs ? (
              <div className="space-y-2">
                <p>{aiText(aiJs, "summary")}</p>
                <div className="flex flex-wrap gap-1.5">
                  {aiObjects(aiJs, "routes").slice(0, 8).map((item, index) => (
                    <span key={`${String(item.url)}-${index}`} className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10.5px] text-slate-500">
                      {String(item.method ?? "GET")} {String(item.url ?? "")}
                      {item.verified ? " · live" : " · unverified"}
                    </span>
                  ))}
                </div>
                {aiList(aiJs, "exposures").length ? (
                  <ul className="list-disc space-y-1 pl-4">
                    {aiList(aiJs, "exposures").slice(0, 5).map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ) : null}
          </AiBlock>

          <AiBlock title="API intelligence" analysis={aiApi} empty="Review API flows, risks and BOLA candidates.">
            {aiApi ? (
              <div className="space-y-2">
                <p>{aiText(aiApi, "summary")}</p>
                {aiList(aiApi, "auth_flows").length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {aiList(aiApi, "auth_flows").map((item) => (
                      <span key={item} className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 text-[10.5px] text-slate-500">
                        {item}
                      </span>
                    ))}
                  </div>
                ) : null}
                {aiList(aiApi, "risks").length ? (
                  <ul className="list-disc space-y-1 pl-4">
                    {aiList(aiApi, "risks").slice(0, 5).map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                ) : null}
                {aiList(aiApi, "bola_candidates").length ? (
                  <p className="text-slate-500">
                    BOLA candidates: {aiList(aiApi, "bola_candidates").slice(0, 3).join(" · ")}
                  </p>
                ) : null}
              </div>
            ) : null}
          </AiBlock>
        </div>
        {aiError ? (
          <div className="px-5 pb-4">
            <Notice tone="danger">{aiError}</Notice>
          </div>
        ) : null}
      </Card>

      <Card className="mt-4">
        <CardHeader
          title="Ask about this scan"
          subtitle="Scoped assistant: answers only from this scan's data. External targets and prompt-injection attempts are refused."
        />
        <div className="space-y-3 px-5 py-4 text-[12.5px] leading-relaxed text-slate-600">
          {chat.length === 0 ? (
            <p className="text-slate-500">
              Try &ldquo;Which finding is most urgent?&rdquo; or &ldquo;What does the CSP finding mean?&rdquo;
            </p>
          ) : (
            <div className="space-y-2.5">
              {chat.map((entry, index) => (
                <div key={index} className="rounded-[8px] border border-line bg-white/[0.04] px-3 py-2.5">
                  <p className="text-[11px] font-semibold text-slate-400">You asked: {entry.question}</p>
                  <p className={cn("mt-1", entry.answer.refused ? "text-amber-300" : "text-slate-600")}>
                    {entry.answer.answer}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10.5px]">
                    <span
                      className={cn(
                        "rounded-full border px-1.5 py-0.5",
                        entry.answer.refused || entry.answer.fallback
                          ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                          : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
                      )}
                    >
                      {entry.answer.refused ? "refused" : entry.answer.fallback ? "deterministic fallback" : "model grounded"}
                    </span>
                    <span className="rounded-full border border-line bg-white/[0.04] px-1.5 py-0.5 text-slate-500">
                      {entry.answer.provider} · {entry.answer.model} · {entry.answer.prompt_version}
                    </span>
                  </div>
                  {entry.answer.references.length > 0 ? (
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10.5px]">
                      <span className="text-slate-500">Grounded in:</span>
                      {entry.answer.references.slice(0, 8).map((ref) => (
                        <span
                          key={ref}
                          title={ref}
                          className="max-w-[220px] truncate rounded-full border border-cyan-500/25 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-cyan-300"
                        >
                          {ref}
                        </span>
                      ))}
                      {entry.answer.references.length > 8 ? (
                        <span className="text-slate-500">+{entry.answer.references.length - 8}</span>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-2">
            <input
              className="field"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !asking && question.trim().length >= 3) ask();
              }}
              placeholder="Ask about a finding, endpoint or risk in this scan"
            />
            <Button onClick={ask} disabled={asking || question.trim().length < 3}>
              {asking ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
              Ask
            </Button>
          </div>
        </div>
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <Card className="min-w-0 lg:col-span-3">
          <CardHeader
            title="Findings"
            subtitle={`${scan.findings_total} result(s), highest risk first`}
            action={
              scan.findings.length > 0 ? (
                <Link href={`/findings?scan=${scan.id}`} className="text-[12px] font-medium text-brand-ring">
                  All findings
                </Link>
              ) : null
            }
          />
          {scan.findings.length === 0 ? (
            <div className="px-5 py-10 text-center">
              <ShieldAlert size={20} className="mx-auto text-slate-300" />
              <p className="mt-2 text-[13px] font-medium text-ink">
                {active ? "Analysis in progress" : "No findings recorded"}
              </p>
              <p className="mx-auto mt-1 max-w-sm text-[12px] leading-relaxed text-slate-500">
                {active
                  ? "Findings appear here as each check finishes, with severity and evidence."
                  : "The enabled checks did not produce findings. That is not proof of security — coverage grows with each phase."}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-line">
              {scan.findings.map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="block px-5 py-3.5 transition hover:bg-white/[0.03]"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-[13px] font-medium leading-snug text-ink">{finding.title}</p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-400">
                        {finding.check_id} · {finding.url}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="rounded-[6px] bg-white/[0.04] px-1.5 py-0.5 text-[10.5px] font-semibold tabular-nums text-slate-500">
                        {finding.risk_score.toFixed(1)}
                      </span>
                      <SeverityBadge severity={finding.severity} />
                    </div>
                  </div>
                  <div className="mt-1.5 flex items-center gap-2 text-[11px] text-slate-400">
                    <VerificationBadge status={finding.verification_status} />
                    <span>confidence {finding.confidence}/10</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>

        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Event timeline" subtitle={`${events.length} events`} />
            <div className="max-h-[420px] overflow-y-auto px-5 py-4">
              {events.length === 0 ? (
                <p className="py-6 text-center text-[12px] text-slate-400">Waiting for the first event…</p>
              ) : (
                <ol className="relative space-y-4 border-l border-line pl-4">
                  {[...events].reverse().map((event) => (
                    <li key={event.id} className="relative">
                      <span
                        className={cn(
                          "absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full ring-2 ring-white",
                          event.type === "findings"
                            ? "bg-severity-medium"
                            : event.type === "check_failed" || event.type === "scan_completed" && scan.status === "completed"
                              ? "bg-emerald-500"
                              : event.type === "warning"
                                ? "bg-severity-high"
                                : "bg-brand",
                        )}
                      />
                      <p className="text-[12px] leading-snug text-slate-700">{event.message || event.type}</p>
                      <p className="mt-0.5 flex items-center gap-1.5 text-[10.5px] text-slate-400">
                        <Clock size={10} /> {relativeTime(event.created_at)} · {phaseLabels[event.phase] ?? event.phase}
                        {" · "}
                        {event.progress}%
                      </p>
                    </li>
                  ))}
                </ol>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader title="Detected technologies" />
            <div className="flex flex-wrap gap-1.5 px-5 py-4">
              {scan.technologies.length === 0 ? (
                <p className="text-[12px] text-slate-400">None fingerprint yet.</p>
              ) : (
                scan.technologies.map((tech) => (
                  <span
                    key={tech.name}
                    className="inline-flex items-center gap-1 rounded-full border border-line bg-white/[0.04] px-2.5 py-1 text-[11.5px] text-slate-600"
                  >
                    <Server size={11} /> {tech.name}
                    {tech.version ? <span className="text-slate-400">{tech.version}</span> : null}
                  </span>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>

      <Card className="mt-4">
        <CardHeader
          title="Reconnaissance"
          subtitle="DNS, IP intelligence, WAF, registration and crawl coverage"
          action={
            crawl.stopped ? (
              <span className="rounded-full border border-amber-400/25 bg-amber-500/10 px-2 py-0.5 text-[10.5px] font-medium text-amber-300">
                {crawl.stopped}
              </span>
            ) : null
          }
        />
        <div className="grid gap-px bg-line/60 sm:grid-cols-2 xl:grid-cols-4">
          <ReconCell icon={<Network size={13} />} title="DNS">
            {dnsEntries.length === 0 ? (
              <p className="text-[12px] text-slate-400">
                {recon.dns?.error ?? "No DNS records returned."}
              </p>
            ) : (
              <dl className="space-y-1.5">
                {dnsEntries.map(([type, values]) => (
                  <div key={type} className="flex gap-2 text-[11.5px]">
                    <dt className="w-11 shrink-0 font-medium text-slate-500">{type}</dt>
                    <dd className="min-w-0 break-all font-mono text-[11px] text-slate-700">
                      {values.join(", ")}
                    </dd>
                  </div>
                ))}
                {recon.dns?.mail?.dmarc ? (
                  <ReconRow
                    label="DMARC"
                    value={[
                      recon.dns.mail.dmarc.policy ?? "none",
                      recon.dns.mail.dmarc.subdomain_policy
                        ? `sp=${recon.dns.mail.dmarc.subdomain_policy}`
                        : null,
                      recon.dns.mail.dmarc.percentage
                        ? `${recon.dns.mail.dmarc.percentage}%`
                        : null,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  />
                ) : null}
                {recon.dns?.mail?.dkim?.length ? (
                  <ReconRow
                    label="DKIM"
                    value={recon.dns.mail.dkim
                      .map((entry) => `${entry.selector}${entry.revoked ? " (revoked)" : ""}`)
                      .join(", ")}
                  />
                ) : null}
              </dl>
            )}
          </ReconCell>
          <ReconCell icon={<Waypoints size={13} />} title="IP intelligence">
            {ipIntel.addresses?.length ? (
              <dl className="space-y-1.5">
                {ipIntel.addresses.slice(0, 4).map((address) => (
                  <div
                    key={address.address}
                    className="flex items-start justify-between gap-2 text-[11.5px]"
                  >
                    <dt className="min-w-0 break-all font-mono text-[11px] text-slate-700">
                      {address.address}
                    </dt>
                    <dd className="shrink-0 text-right text-[10.5px] text-slate-400">
                      {address.asn ? (
                        <>
                          <span className="block">
                            {address.asn}
                            {address.country ? ` · ${address.country}` : ""}
                          </span>
                          {address.ptr ? (
                            <span className="block max-w-[160px] truncate" title={address.ptr}>
                              {address.ptr}
                            </span>
                          ) : null}
                        </>
                      ) : (
                        (address.ptr ?? address.scope)
                      )}
                    </dd>
                  </div>
                ))}
                {ipIntel.hosting?.length ? (
                  <ReconRow label="Hosting" value={ipIntel.hosting.join(", ")} />
                ) : null}
                {exposure.map((item) => (
                  <ReconRow
                    key={item.address}
                    label={item.source}
                    value={
                      item.error
                        ? item.error
                        : `${item.ports.length} port(s)${item.vulns.length ? ` · ${item.vulns.length} CVE(s)` : ""}`
                    }
                  />
                ))}
                {neighbours.hosts?.length ? (
                  <ReconRow
                    label="Neighbours"
                    value={`${neighbours.count ?? neighbours.hosts.length} PTR · ${neighbours.prefix ?? ""}`}
                  />
                ) : null}
              </dl>
            ) : (
              <p className="text-[12px] text-slate-400">
                {ipIntel.error ?? "No IP addresses resolved."}
              </p>
            )}
          </ReconCell>
          <ReconCell icon={<Radar size={13} />} title="WAF / edge">
            {waf.vendors?.length ? (
              <dl className="space-y-1.5">
                {waf.vendors.map((vendor) => (
                  <div key={vendor.name} className="flex items-center justify-between gap-2 text-[11.5px]">
                    <dt className="font-medium text-slate-700" title={vendor.evidence.join(", ")}>
                      {vendor.name}
                    </dt>
                    <dd className="rounded bg-white/[0.04] px-1.5 py-0.5 text-[10px] text-slate-500">
                      {vendor.category} · {Math.round(vendor.confidence * 100)}%
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="text-[12px] text-slate-400">
                {waf.summary ?? "No WAF or edge fingerprint matched."}
              </p>
            )}
          </ReconCell>
          <ReconCell icon={<ShieldCheck size={13} />} title="Transport">
            {tls.protocol ? (
              <dl className="space-y-1.5">
                <ReconRow label="Protocol" value={tls.protocol} />
                <ReconRow label="Cipher" value={tls.cipher ?? "—"} />
                <ReconRow label="Issuer" value={tls.issuer ?? "—"} />
                <ReconRow
                  label="Expires"
                  value={tls.days_to_expiry != null ? `${tls.days_to_expiry} day(s)` : "—"}
                />
                <ReconRow
                  label="Trust"
                  value={tls.verified ? "valid chain" : (tls.error ?? "unverified")}
                />
              </dl>
            ) : (
              <p className="text-[12px] text-slate-400">
                {tls.error ?? "No TLS handshake (HTTP target)."}
              </p>
            )}
          </ReconCell>
          <ReconCell icon={<Crosshair size={13} />} title="Crawl coverage">
            <dl className="space-y-1.5">
              <ReconRow label="Pages" value={crawl.pages ?? 0} />
              <ReconRow label="Links" value={crawl.links ?? 0} />
              <ReconRow label="Forms" value={crawl.forms ?? 0} />
              <ReconRow label="JS endpoints" value={crawl.js_endpoints ?? 0} />
              <ReconRow label="API paths" value={crawl.api_endpoints ?? 0} />
              <ReconRow label="Dir hits" value={dirs?.found ?? 0} />
            </dl>
          </ReconCell>
          <ReconCell icon={<BadgeCheck size={13} />} title="Verification">
            {verificationTotal === 0 ? (
              <p className="text-[12px] text-slate-400">No findings to verify yet.</p>
            ) : (
              <div className="space-y-1.5">
                <ReconRow label="Verified" value={verification.verified ?? 0} />
                <ReconRow label="Suspected" value={verification.suspected ?? 0} />
                {(verification.downgraded ?? 0) > 0 ? (
                  <p className="text-[11px] text-amber-300">
                    {verification.downgraded} finding(s) downgraded for incomplete evidence
                  </p>
                ) : (
                  <p className="text-[11px] text-slate-400">
                    Every verified finding carries its confirmation evidence.
                  </p>
                )}
              </div>
            )}
          </ReconCell>
          <ReconCell icon={<FileCode2 size={13} />} title="Robots & specs">
            <dl className="space-y-1.5">
              <ReconRow
                label="robots.txt"
                value={crawl.robots_found || robots.url ? "found" : "not found"}
              />
              <ReconRow label="Sitemap URLs" value={crawl.sitemap_urls ?? 0} />
              <ReconRow label="API specs" value={crawl.api_specs ?? 0} />
              <ReconRow label="Probes" value={crawl.probed ?? 0} />
            </dl>
          </ReconCell>
          <ReconCell icon={<FileJson size={13} />} title="API surface">
            {apiDocuments.length === 0 ? (
              <p className="text-[12px] text-slate-400">No API specification discovered.</p>
            ) : (
              <dl className="space-y-1.5">
                {apiDocuments.slice(0, 2).map((document) => (
                  <div key={document.url} className="space-y-1.5">
                    <ReconRow
                      label="Spec"
                      value={document.title || document.url.split("/").pop() || "API"}
                    />
                    <ReconRow label="Routes" value={document.paths ?? 0} />
                    <ReconRow
                      label="Auth"
                      value={
                        document.declared_auth
                          ? (document.security_schemes?.[0] ?? "declared")
                          : "none declared"
                      }
                    />
                  </div>
                ))}
                <ReconRow label="Documented calls" value={apiSurface.endpoint_count ?? 0} />
              </dl>
            )}
          </ReconCell>
          <ReconCell icon={<ShieldCheck size={13} />} title="API security intelligence">
            {!apiHasIntel ? (
              <p className="text-[12px] text-slate-400">
                No API contract, JWT or GraphQL surface observed.
              </p>
            ) : (
              <div className="space-y-1.5">
                {(apiIntel.spec?.documents ?? 0) > 0 ? (
                  <>
                    <ReconRow label="Public writes" value={apiIntel.spec?.public_write_count ?? 0} />
                    <ReconRow label="Public reads" value={apiIntel.spec?.public_reads ?? 0} />
                    {(apiIntel.spec?.api_key_query_schemes ?? []).length > 0 ? (
                      <p
                        className="truncate text-[10.5px] text-amber-300"
                        title={(apiIntel.spec?.api_key_query_schemes ?? []).join(", ")}
                      >
                        key in query: {(apiIntel.spec?.api_key_query_schemes ?? []).join(", ")}
                      </p>
                    ) : null}
                    {(apiIntel.spec?.public_writes ?? []).slice(0, 3).map((operation) => (
                      <p
                        key={`${operation.method}-${operation.path}`}
                        className="truncate font-mono text-[10.5px] text-slate-500"
                        title={operation.path}
                      >
                        {operation.method} {operation.path}
                      </p>
                    ))}
                  </>
                ) : null}
                {apiTokens.length > 0 ? (
                  <>
                    <ReconRow
                      label="JWT tokens"
                      value={`${apiTokens.length} (${apiTokens.filter((token) => token.flags.length > 0).length} flagged)`}
                    />
                    {apiTokens.slice(0, 2).map((token) => (
                      <p
                        key={token.fingerprint}
                        className={cn(
                          "truncate font-mono text-[10.5px]",
                          token.flags.length > 0 ? "text-amber-300" : "text-slate-500",
                        )}
                        title={token.source}
                      >
                        {token.alg} · {token.location} · {token.flags.join(", ") || "no flags"}
                      </p>
                    ))}
                  </>
                ) : null}
                {(apiGraphql?.probed ?? 0) > 0 ? (
                  <>
                    <ReconRow
                      label="GraphQL"
                      value={`${(apiGraphql?.confirmed ?? []).length} of ${apiGraphql?.probed} probed`}
                    />
                    <ReconRow
                      label="Introspection"
                      value={
                        apiGraphql?.introspection
                          ? `enabled (${apiGraphql?.type_count ?? 0} types)`
                          : "not observed"
                      }
                    />
                    {apiGraphql?.ide ? (
                      <p className="text-[10.5px] text-amber-300">IDE exposed</p>
                    ) : null}
                  </>
                ) : null}
              </div>
            )}
          </ReconCell>
          <ReconCell icon={<Terminal size={13} />} title="JS bundle intelligence">
            {(jsIntel.scripts ?? 0) === 0 ? (
              <p className="text-[12px] text-slate-400">No JavaScript bundles analyzed.</p>
            ) : (
              <div className="space-y-1.5">
                <ReconRow label="Scripts" value={jsIntel.scripts ?? 0} />
                <ReconRow
                  label="API call sites"
                  value={`${jsIntel.api_calls ?? 0} (${jsIntel.post_calls ?? 0} non-GET)`}
                />
                <ReconRow label="Source maps" value={(jsIntel.source_maps ?? []).length} />
                {(jsIntel.source_maps ?? []).slice(0, 2).map((map) => (
                  <p
                    key={map.url}
                    className="truncate font-mono text-[10.5px] text-slate-500"
                    title={map.url}
                  >
                    {map.url.split("/").pop() ?? map.url} · {map.same_origin ? "same origin" : "third-party"}
                  </p>
                ))}
                {(jsIntel.sensitive_paths ?? []).length > 0 ? (
                  <p className="truncate text-[10.5px] text-amber-300" title={(jsIntel.sensitive_paths ?? []).join(", ")}>
                    sensitive: {(jsIntel.sensitive_paths ?? []).slice(0, 4).join(", ")}
                  </p>
                ) : null}
                {(jsIntel.parameters ?? []).length > 0 ? (
                  <p className="truncate font-mono text-[10.5px] text-slate-500" title={(jsIntel.parameters ?? []).join(", ")}>
                    params: {(jsIntel.parameters ?? []).slice(0, 8).join(", ")}
                  </p>
                ) : null}
                {(jsIntel.third_party_hosts ?? []).length > 0 ? (
                  <p className="truncate text-[10.5px] text-slate-500" title={(jsIntel.third_party_hosts ?? []).join(", ")}>
                    third-party: {(jsIntel.third_party_hosts ?? []).slice(0, 3).join(", ")}
                  </p>
                ) : null}
              </div>
            )}
          </ReconCell>
          <ReconCell icon={<Globe size={13} />} title="Subdomains">
            {!subdomains.domain ? (
              <p className="text-[12px] text-slate-400">
                No public-domain certificate lookup for this target.
              </p>
            ) : (subdomains.names?.length ?? 0) > 0 ? (
              <div className="space-y-1.5">
                {subdomains.names?.slice(0, 4).map((name) => (
                  <p key={name} className="truncate font-mono text-[11px] text-slate-700">
                    {name}
                  </p>
                ))}
                {(subdomains.count ?? 0) > 4 ? (
                  <p className="text-[10.5px] text-slate-400">
                    +{(subdomains.count ?? 0) - 4} more
                    {subdomains.wildcard ? " · wildcard certificate" : ""}
                  </p>
                ) : null}
              </div>
            ) : (
              <p className="text-[12px] text-slate-400">
                {subdomains.error ?? "No subdomains in certificate transparency."}
              </p>
            )}
          </ReconCell>
          <ReconCell icon={<History size={13} />} title="Historic URLs">
            {!history.domain ? (
              <p className="text-[12px] text-slate-400">
                No public-domain archive lookup for this target.
              </p>
            ) : (history.urls?.length ?? 0) > 0 ? (
              <div className="space-y-1.5">
                <ReconRow label="Archived" value={history.count ?? history.urls?.length ?? 0} />
                <ReconRow
                  label="API-like"
                  value={(history.urls ?? []).filter((item) => item.kind === "api").length}
                />
                {(history.urls ?? []).slice(0, 3).map((item) => (
                  <p
                    key={item.url}
                    className="truncate font-mono text-[11px] text-slate-700"
                    title={item.url}
                  >
                    {item.url}
                  </p>
                ))}
              </div>
            ) : (
              <p className="text-[12px] text-slate-400">
                {history.error ?? "No archived URLs found."}
              </p>
            )}
          </ReconCell>
          <ReconCell icon={<AtSign size={13} />} title="Domain registration">
            {whois.domain ? (
              whois.error ? (
                <p className="text-[12px] text-slate-400">{whois.error}</p>
              ) : (
                <dl className="space-y-1.5">
                  <ReconRow label="Registrar" value={whois.registrar ?? "—"} />
                  <ReconRow label="Created" value={whois.created?.slice(0, 10) ?? "—"} />
                  <ReconRow label="Expires" value={whois.expires?.slice(0, 10) ?? "—"} />
                  {whois.statuses?.length ? (
                    <ReconRow label="Status" value={whois.statuses[0]} />
                  ) : null}
                </dl>
              )
            ) : (
              <p className="text-[12px] text-slate-400">No public-domain registration lookup for this target.</p>
            )}
          </ReconCell>
        </div>
      </Card>

      <Card className="mt-4 overflow-hidden">
        <CardHeader
          title="Attack surface graph"
          subtitle="Endpoints grouped by discovery source"
          action={
            <span className="inline-flex items-center gap-1 text-[11.5px] text-slate-400">
              <Waypoints size={12} /> {visibleEndpoints.length}
              {endpointSource !== "all" ? ` · ${endpointSource}` : ""}
            </span>
          }
        />
        <div className="border-t border-line">
          <SurfaceGraph endpoints={visibleEndpoints} targetUrl={scan.target_url} />
        </div>
      </Card>

      {endpointClusters.length > 0 ? (
        <Card className="mt-4">
          <CardHeader
            title="Endpoint clusters"
            subtitle={`${endpointIntel.cluster_count ?? endpointClusters.length} patterns · ${
              endpointIntel.templated ?? 0
            } parameterised · ${endpointIntel.api_clusters ?? 0} API-like`}
            action={
              <span className="inline-flex items-center gap-1 text-[11.5px] text-slate-400">
                <Layers size={12} /> {endpointIntel.endpoint_count ?? scan.endpoints.length}
              </span>
            }
          />
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] border-collapse text-sm">
              <thead>
                <tr className="table-head">
                  <th className="px-5 py-2.5">Template</th>
                  <th className="px-4 py-2.5">Endpoints</th>
                  <th className="px-4 py-2.5">Methods</th>
                  <th className="px-4 py-2.5">Sources</th>
                  <th className="px-4 py-2.5">Parameters</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {endpointClusters.map((cluster) => (
                  <tr key={cluster.template}>
                    <td className="max-w-[380px] truncate px-5 py-2.5 font-mono text-[11.5px] text-slate-700">
                      {cluster.template}
                    </td>
                    <td className="px-4 py-2.5 text-[11.5px] tabular-nums text-slate-500">
                      {cluster.count}
                    </td>
                    <td className="px-4 py-2.5 text-[11.5px] text-slate-500">
                      {cluster.methods.join(", ")}
                    </td>
                    <td className="px-4 py-2.5 text-[11.5px] capitalize text-slate-500">
                      {cluster.sources.join(", ")}
                    </td>
                    <td className="max-w-[220px] truncate px-4 py-2.5 font-mono text-[11px] text-slate-500">
                      {cluster.parameters.length ? cluster.parameters.join(", ") : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}

      <Card className="mt-4">
        <CardHeader
          title="Discovered endpoints"
          subtitle="Live responses separated from references that were never fetched"
          action={
            <span className="inline-flex items-center gap-2 text-[11.5px] text-slate-400">
              <Crosshair size={12} /> {scan.endpoints.length}
              {unverifiedEndpointCount > 0 ? (
                <span className="rounded-full border border-line bg-panel px-2 py-0.5 text-[10.5px]">
                  {liveEndpointCount} live · {unverifiedEndpointCount} unverified
                </span>
              ) : null}
            </span>
          }
        />
        {scan.endpoints.length === 0 ? (
          <p className="px-5 py-8 text-center text-[12.5px] text-slate-400">No endpoints recorded yet.</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-5 py-3">
              {["all", ...endpointSources].map((source) => (
                <button
                  key={source}
                  type="button"
                  onClick={() => setEndpointSource(source)}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-[10.5px] font-medium capitalize transition",
                    endpointSource === source
                      ? "border-brand-ring/40 bg-brand/15 text-brand-ring"
                      : "border-line bg-panel text-slate-500 hover:text-ink",
                  )}
                >
                  {source === "all" ? `All ${scan.endpoints.length}` : source}
                </button>
              ))}
              {unverifiedEndpointCount > 0 ? (
                <span className="ml-auto flex gap-1.5">
                  {(["all", "live", "unverified"] as const).map((state) => (
                    <button
                      key={state}
                      type="button"
                      onClick={() => setEndpointState(state)}
                      className={cn(
                        "rounded-full border px-2.5 py-1 text-[10.5px] font-medium capitalize transition",
                        endpointState === state
                          ? "border-brand-ring/40 bg-brand/15 text-brand-ring"
                          : "border-line bg-panel text-slate-500 hover:text-ink",
                      )}
                    >
                      {state === "all" ? "Any state" : state}
                    </button>
                  ))}
                </span>
              ) : null}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[880px] border-collapse text-sm">
                <thead>
                  <tr className="table-head">
                    <th className="px-5 py-2.5">URL</th>
                    <th className="px-4 py-2.5">Method</th>
                    <th className="px-4 py-2.5">Source</th>
                    <th className="px-4 py-2.5">Surface</th>
                    <th className="px-4 py-2.5">Depth</th>
                    <th className="px-4 py-2.5">Parameters</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5">Content type</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {visibleEndpoints.map((endpoint) => {
                    const surface = endpointSurfaceState(endpoint);
                    return (
                      <tr key={`${endpoint.method}-${endpoint.url}`}>
                        <td className="max-w-[360px] truncate px-5 py-2.5 font-mono text-[11.5px] text-slate-700">
                          {endpoint.url}
                        </td>
                        <td className="px-4 py-2.5 text-[11.5px] text-slate-500">{endpoint.method}</td>
                        <td className="px-4 py-2.5 text-[11.5px] capitalize text-slate-500">
                          {endpoint.source}
                        </td>
                        <td className="px-4 py-2.5">
                          <span
                            className={cn(
                              "rounded-full border px-2 py-0.5 text-[10px] font-medium",
                              surface === "live"
                                ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                                : "border-line bg-panel text-slate-400",
                            )}
                          >
                            {surface}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-[11.5px] tabular-nums text-slate-500">
                          {endpoint.depth}
                        </td>
                        <td className="max-w-[220px] truncate px-4 py-2.5 font-mono text-[11px] text-slate-500">
                          {endpoint.parameters.length ? endpoint.parameters.join(", ") : "—"}
                        </td>
                        <td className="px-4 py-2.5 text-[11.5px] tabular-nums text-slate-500">
                          {endpoint.status_code ?? "—"}
                        </td>
                        <td className="px-4 py-2.5 text-[11.5px] text-slate-500">
                          {endpoint.content_type?.split(";")[0] ?? "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {visibleEndpoints.length === 0 ? (
                <p className="px-5 py-8 text-center text-[12.5px] text-slate-400">
                  No endpoints match this filter.
                </p>
              ) : null}
            </div>
          </>
        )}
        {(surfaceHints.cookies?.length ||
          surfaceHints.form_parameters?.length ||
          surfaceHints.query_parameters?.length) ? (
          <div className="space-y-2 border-t border-line px-5 py-3.5">
            <p className="text-[10.5px] font-medium uppercase tracking-[0.16em] text-slate-400">
              Parameter hints
            </p>
            {surfaceHints.query_parameters?.length ? (
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                <span className="w-16 shrink-0 text-slate-400">Query</span>
                {surfaceHints.query_parameters.slice(0, 12).map((name) => (
                  <span
                    key={`q-${name}`}
                    className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 font-mono text-[10.5px]"
                  >
                    {name}
                  </span>
                ))}
              </div>
            ) : null}
            {surfaceHints.form_parameters?.length ? (
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                <span className="w-16 shrink-0 text-slate-400">Form</span>
                {surfaceHints.form_parameters.slice(0, 12).map((name) => (
                  <span
                    key={`f-${name}`}
                    className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 font-mono text-[10.5px]"
                  >
                    {name}
                  </span>
                ))}
              </div>
            ) : null}
            {surfaceHints.cookies?.length ? (
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                <span className="w-16 shrink-0 text-slate-400">Cookies</span>
                {surfaceHints.cookies.slice(0, 12).map((name) => (
                  <span
                    key={`c-${name}`}
                    className="rounded-full border border-line bg-white/[0.04] px-2 py-0.5 font-mono text-[10.5px]"
                  >
                    {name}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
        <div className="border-t border-line px-5 py-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-[10.5px] font-medium uppercase tracking-[0.16em] text-slate-400">
              Endpoint learning
            </p>
            <Button size="sm" variant="secondary" onClick={toggleEndpointLearning} disabled={learningBusy}>
              {learningBusy ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <GraduationCap size={13} />
              )}
              {learningOpen ? "Hide lessons" : "Learn this surface"}
            </Button>
          </div>
          {learningError ? (
            <div className="mt-2">
              <Notice tone="danger">{learningError}</Notice>
            </div>
          ) : null}
          {learningOpen && endpointLearning ? (
            <div className="mt-3 space-y-2.5">
              <p className="text-[11.5px] text-slate-500">
                {endpointLearning.with_findings} of {endpointLearning.endpoint_count} endpoint(s) carry
                a lesson. Each card explains what the check saw and how to verify it by hand on an
                authorized target.
              </p>
              {endpointLearning.endpoints.filter((entry) => entry.lessons.length > 0).length === 0 ? (
                <p className="text-[12px] text-slate-400">
                  No findings mapped to endpoints in this scan yet.
                </p>
              ) : (
                endpointLearning.endpoints
                  .filter((entry) => entry.lessons.length > 0)
                  .slice(0, 8)
                  .map((entry) => (
                    <div
                      key={`${entry.method}-${entry.url}`}
                      className="rounded-[8px] border border-line bg-white/[0.03] px-3 py-2.5"
                    >
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="max-w-[420px] truncate font-mono text-[11px] text-slate-700">
                          {entry.method} {entry.url}
                        </span>
                        <span className="rounded-full border border-line bg-panel px-1.5 py-0.5 text-[10px] text-slate-500">
                          {entry.state}
                        </span>
                      </div>
                      <ul className="mt-2 space-y-1.5">
                        {entry.lessons.map((lesson) => (
                          <li key={lesson.finding_id} className="text-[11.5px] leading-relaxed">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <SeverityBadge severity={lesson.severity} />
                              <span className="font-medium text-slate-700">{lesson.title}</span>
                              <VerificationBadge status={lesson.verification_status} />
                            </div>
                            {lesson.why ? (
                              <p className="mt-0.5 text-slate-500">Why it matters: {lesson.why}</p>
                            ) : null}
                            {lesson.verify ? (
                              <p className="text-slate-500">Verify: {lesson.verify}</p>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))
              )}
            </div>
          ) : null}
        </div>
      </Card>

      <ScanExtras scanId={scan.id} targetId={scan.target_id} />

      <div className="mt-4 flex items-center justify-between text-[11.5px] text-slate-400">
        <span className="flex items-center gap-1">
          <Globe size={12} /> {scan.target_url}
        </span>
        <span>
          Started {formatDate(scan.started_at ?? scan.created_at)}
          {scan.finished_at ? ` · finished ${formatDate(scan.finished_at)}` : ""}
        </span>
      </div>
    </div>
  );
}

function aiText(analysis: AiAnalysis, key: string): string {
  const value = analysis.payload[key];
  return typeof value === "string" ? value : "";
}

function aiList(analysis: AiAnalysis, key: string): string[] {
  const value = analysis.payload[key];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function aiObjects(analysis: AiAnalysis, key: string): Record<string, unknown>[] {
  const value = analysis.payload[key];
  return Array.isArray(value)
    ? value.filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null)
    : [];
}

function aiOrder(analysis: AiAnalysis): { finding_id: string; title: string; reason?: string }[] {
  const value = analysis.payload.order;
  if (!Array.isArray(value)) return [];
  return value.filter(
    (item): item is { finding_id: string; title: string; reason?: string } =>
      typeof item === "object" && item !== null && typeof item.title === "string",
  );
}

function AiBlock({
  title,
  analysis,
  empty,
  children,
}: {
  title: string;
  analysis?: AiAnalysis;
  empty: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-[9px] border border-line bg-panel px-4 py-3">
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">{title}</p>
        {analysis ? (
          <span
            className={cn(
              "rounded-full border px-1.5 py-0.5 text-[10px]",
              analysis.fallback
                ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
            )}
          >
            {analysis.fallback ? "deterministic" : `${analysis.provider} · ${analysis.model}`}
          </span>
        ) : null}
      </div>
      {analysis ? (
        <div className="text-[12px] leading-relaxed text-slate-600">{children}</div>
      ) : (
        <p className="text-[12px] text-slate-500">{empty}</p>
      )}
    </div>
  );
}

function StatPill({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
}) {
  return (
    <div className="px-4 py-3">
      <p className="flex items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-[0.08em] text-slate-400">
        {icon} {label}
      </p>
      <p className="mt-1 text-[18px] font-semibold tabular-nums text-ink">{value}</p>
    </div>
  );
}

function ReconCell({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-panel px-5 py-4">
      <p className="mb-2.5 flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-slate-400">
        {icon} {title}
      </p>
      {children}
    </div>
  );
}

function ReconRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-start justify-between gap-3 text-[11.5px]">
      <dt className="shrink-0 text-slate-500">{label}</dt>
      <dd className="min-w-0 truncate text-right font-medium text-slate-700">{value}</dd>
    </div>
  );
}
