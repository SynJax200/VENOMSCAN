"use client";

import {
  BookOpenCheck,
  CheckCircle2,
  Compass,
  GraduationCap,
  Loader2,
  Map,
  Puzzle,
  Search,
  Sparkles,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { ProfileBadge, SeverityBadge } from "@/components/badges";
import { Badge, Button, Card, CardHeader, Notice, Skeleton } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type {
  AiAnalysis,
  CheckInfo,
  LearningLesson,
  LearningPaths,
  LearningStatus,
  PluginCatalog,
  PracticeExercise,
  PracticeFinding,
  ScanProfile,
  Walkthrough,
} from "@/lib/types";
import { cn } from "@/lib/utils";

interface EducationNote {
  plain_language?: string;
  why_it_matters?: string;
  how_to_verify?: string;
  practice_tip?: string;
}

const profileFilters: (ScanProfile | "all")[] = ["all", "passive", "safe", "active"];

const statusStyles: Record<LearningStatus, string> = {
  completed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  in_progress: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  not_started: "border-line bg-panel text-slate-500 hover:text-ink",
};

function progressWidth(percent: number) {
  return `${Math.max(0, Math.min(100, percent))}%`;
}

export default function LearningPage() {
  const [checks, setChecks] = useState<CheckInfo[] | null>(null);
  const [plugins, setPlugins] = useState<PluginCatalog | null>(null);
  const [paths, setPaths] = useState<LearningPaths | null>(null);
  const [practice, setPractice] = useState<PracticeFinding[] | null>(null);
  const [profile, setProfile] = useState<ScanProfile | "all">("all");
  const [query, setQuery] = useState("");
  const [notes, setNotes] = useState<Record<string, AiAnalysis>>({});
  const [aiBusy, setAiBusy] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [lessonBusy, setLessonBusy] = useState<string | null>(null);
  const [pathError, setPathError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [walkthrough, setWalkthrough] = useState<Walkthrough | null>(null);
  const [walkBusy, setWalkBusy] = useState(false);
  const [exercises, setExercises] = useState<PracticeExercise[] | null>(null);
  const [exerciseBusy, setExerciseBusy] = useState(false);
  const [answers, setAnswers] = useState<Record<string, string[]>>({});
  const [checked, setChecked] = useState<Record<string, boolean>>({});

  async function runEducation(checkId: string) {
    setAiBusy(checkId);
    setAiError(null);
    try {
      const row = await api.post<AiAnalysis>(`/api/checks/${checkId}/ai/education`);
      setNotes((current) => ({ ...current, [checkId]: row }));
    } catch (err) {
      setAiError(err instanceof ApiError ? err.detail : "Could not generate the AI learning note");
    } finally {
      setAiBusy(null);
    }
  }

  async function setLessonStatus(checkId: string, current: LearningStatus, target: LearningStatus) {
    const next: LearningStatus = current === target ? "not_started" : target;
    setLessonBusy(checkId);
    setPathError(null);
    try {
      await api.put(`/api/learning/progress/${checkId}`, { status: next });
      setPaths(await api.get<LearningPaths>("/api/learning/paths"));
    } catch (err) {
      setPathError(err instanceof ApiError ? err.detail : "Could not save your learning progress");
    } finally {
      setLessonBusy(null);
    }
  }

  async function openWalkthrough(findingId: string) {
    setSelectedFinding(findingId);
    setWalkthrough(null);
    setExercises(null);
    setAnswers({});
    setChecked({});
    setWalkBusy(true);
    setAiError(null);
    try {
      setWalkthrough(await api.post<Walkthrough>(`/api/learning/findings/${findingId}/walkthrough`));
    } catch (err) {
      setAiError(err instanceof ApiError ? err.detail : "Could not build the walkthrough");
    } finally {
      setWalkBusy(false);
    }
  }

  async function loadExercises() {
    if (!walkthrough) return;
    setExerciseBusy(true);
    setAiError(null);
    try {
      setExercises(
        await api.post<PracticeExercise[]>(`/api/learning/findings/${walkthrough.finding_id}/exercises`),
      );
    } catch (err) {
      setAiError(err instanceof ApiError ? err.detail : "Could not build the practice questions");
    } finally {
      setExerciseBusy(false);
    }
  }

  function chooseOption(exercise: PracticeExercise, option: string) {
    if (!exercise.multi) {
      setAnswers((state) => ({ ...state, [exercise.id]: [option] }));
      setChecked((state) => ({ ...state, [exercise.id]: true }));
      return;
    }
    setAnswers((state) => {
      const current = state[exercise.id] ?? [];
      const next = current.includes(option)
        ? current.filter((item) => item !== option)
        : [...current, option];
      return { ...state, [exercise.id]: next };
    });
  }

  function isCorrect(exercise: PracticeExercise) {
    const selection = answers[exercise.id] ?? [];
    return (
      selection.length === exercise.answer.length &&
      exercise.answer.every((value, index) => value === selection[index])
    );
  }

  useEffect(() => {
    Promise.all([
      api.get<CheckInfo[]>("/api/checks"),
      api.get<PluginCatalog>("/api/checks/plugins"),
    ])
      .then(([catalog, pluginCatalog]) => {
        setChecks(catalog);
        setPlugins(pluginCatalog);
      })
      .catch(() => {
        setChecks([]);
        setPlugins({ plugins: [], problems: ["Could not load the check catalogue"], isolation: "" });
      });
  }, []);

  useEffect(() => {
    api
      .get<LearningPaths>("/api/learning/paths")
      .then(setPaths)
      .catch(() => setPaths(null));
    api
      .get<PracticeFinding[]>("/api/learning/practice")
      .then(setPractice)
      .catch(() => setPractice([]));
  }, []);

  const visible = useMemo(() => {
    if (!checks) return [];
    const needle = query.trim().toLowerCase();
    return checks.filter((check) => {
      if (profile !== "all" && check.profile !== profile) return false;
      if (!needle) return true;
      return (
        check.name.toLowerCase().includes(needle) ||
        check.id.toLowerCase().includes(needle) ||
        check.category.toLowerCase().includes(needle)
      );
    });
  }, [checks, profile, query]);

  const counts = useMemo(() => {
    const base: Record<string, number> = { passive: 0, safe: 0, active: 0 };
    for (const check of checks ?? []) base[check.profile] = (base[check.profile] ?? 0) + 1;
    return base;
  }, [checks]);

  return (
    <div>
      <PageHeader
        eyebrow="Learning mode"
        title="Why every check exists"
        description="Follow guided tracks, prove findings against real evidence from your own scans, and complete practice questions before you mark a lesson done."
        actions={
          <Badge tone="bg-brand/10 text-brand-ring border-brand-ring/25">
            <GraduationCap size={12} />{" "}
            {paths ? `${paths.completed}/${paths.check_count} lessons` : `${checks?.length ?? "—"} checks`}
          </Badge>
        }
      />

      {pathError ? (
        <div className="mb-4">
          <Notice tone="danger">{pathError}</Notice>
        </div>
      ) : null}
      {aiError ? (
        <div className="mb-4">
          <Notice tone="danger">{aiError}</Notice>
        </div>
      ) : null}

      {paths ? (
        <Card className="mb-4 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 text-[12px] font-medium text-ink">
              <Map size={14} className="text-brand-ring" /> Overall progress
            </div>
            <div className="h-1.5 min-w-[160px] flex-1 overflow-hidden rounded-full bg-white/10">
              <div className="h-full rounded-full bg-brand" style={{ width: progressWidth(paths.percent) }} />
            </div>
            <div className="flex items-center gap-2 text-[11.5px] text-slate-500">
              <span className="font-semibold text-ink">{paths.percent}%</span>
              <span>{paths.completed} completed</span>
              <span>·</span>
              <span>{paths.in_progress} in progress</span>
              <span>·</span>
              <span>{paths.check_count - paths.completed} to go</span>
            </div>
          </div>
        </Card>
      ) : null}

      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[13px] font-semibold text-ink">Guided tracks</h2>
        <span className="text-[11px] text-slate-500">
          Beginner runs the passive profile, intermediate safe, advanced active with consent.
        </span>
      </div>

      {paths === null ? (
        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <Skeleton className="h-56" />
          <Skeleton className="h-56" />
          <Skeleton className="h-56" />
        </div>
      ) : (
        <div className="mb-6 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {paths.tracks.map((track) => (
            <Card key={track.id} className="flex flex-col p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-[13px] font-semibold text-ink">{track.title}</p>
                  <p className="mt-0.5 text-[10.5px] uppercase tracking-[0.1em] text-slate-500">
                    {track.level} · {track.scan_profile} profile · {track.completed}/{track.total} done
                  </p>
                </div>
                <Badge tone="bg-white/5 text-slate-500 border-line">
                  <Compass size={11} /> {track.percent}%
                </Badge>
              </div>
              <p className="mt-2 text-[11.5px] leading-relaxed text-slate-500">{track.focus}</p>
              <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/10">
                <div className="h-full rounded-full bg-brand" style={{ width: progressWidth(track.percent) }} />
              </div>
              <ul className="mt-3 divide-y divide-line">
                {track.lessons.map((lesson) => (
                  <LessonRow
                    key={lesson.id}
                    lesson={lesson}
                    busy={lessonBusy === lesson.id}
                    onSelect={setLessonStatus}
                  />
                ))}
              </ul>
              <p className="mt-auto space-y-1 pt-3 text-[10.5px] text-slate-500">
                <span className="block">{track.outcome}</span>
                {track.consent ? <span className="block italic">{track.consent}</span> : null}
              </p>
            </Card>
          ))}
        </div>
      )}

      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[13px] font-semibold text-ink">Practice from your scans</h2>
        <span className="text-[11px] text-slate-500">
          Verified findings only · evidence is redacted before it reaches this page.
        </span>
      </div>

      <Card className="mb-6">
        <div className="grid gap-0 lg:grid-cols-[320px_1fr]">
          <div className="border-b border-line p-4 lg:border-b-0 lg:border-r">
            {practice === null ? (
              <div className="flex items-center gap-2 text-[12px] text-slate-400">
                <Loader2 size={14} className="animate-spin" /> Loading verified findings…
              </div>
            ) : practice.length === 0 ? (
              <p className="text-[12px] text-slate-400">
                No verified findings yet. Run a scan on a target you own and verify a finding to unlock a
                walkthrough.
              </p>
            ) : (
              <ul className="space-y-1.5">
                {practice.map((finding) => (
                  <li key={finding.id}>
                    <button
                      type="button"
                      onClick={() => openWalkthrough(finding.id)}
                      className={cn(
                        "w-full rounded-[8px] border px-2.5 py-2 text-left transition",
                        selectedFinding === finding.id
                          ? "border-brand-ring/40 bg-brand/10"
                          : "border-line bg-panel hover:border-brand-ring/30",
                      )}
                    >
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={finding.severity} />
                        <span className="ml-auto text-[10px] text-slate-500">risk {finding.risk_score.toFixed(1)}</span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-[11.5px] font-medium text-ink">{finding.title}</p>
                      <p className="mt-0.5 font-mono text-[10px] text-slate-400">{finding.check_id}</p>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="p-4">
            {walkBusy ? (
              <div className="flex items-center gap-2 text-[12px] text-slate-400">
                <Loader2 size={14} className="animate-spin" /> Building the walkthrough…
              </div>
            ) : walkthrough === null ? (
              <p className="text-[12px] text-slate-400">
                Pick a finding on the left to get a five-step, evidence-grounded walkthrough you can replay
                inside the authorization you own.
              </p>
            ) : (
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <p className="text-[13px] font-semibold text-ink">{walkthrough.title}</p>
                  <SeverityBadge severity={walkthrough.severity} />
                  <Badge tone="bg-white/5 text-slate-500 border-line">
                    {walkthrough.verification_status} · conf {walkthrough.confidence ?? "—"}/10
                  </Badge>
                </div>
                <p className="mt-1 break-all font-mono text-[10.5px] text-slate-400">
                  {walkthrough.method} {walkthrough.url}
                </p>

                <ol className="mt-3 space-y-2">
                  {walkthrough.steps.map((step, index) => (
                    <li key={step.key} className="rounded-[8px] border border-line bg-panel p-3">
                      <p className="text-[12px] font-semibold text-ink">
                        {index + 1}. {step.title}
                      </p>
                      <p className="mt-1 text-[11.5px] leading-relaxed text-slate-600">{step.detail}</p>
                      {Object.keys(step.evidence).length > 0 ? (
                        <dl className="mt-2 space-y-1 rounded-[6px] border border-line/70 bg-black/10 p-2">
                          {Object.entries(step.evidence).map(([key, value]) => (
                            <div key={key} className="flex flex-wrap gap-x-2 text-[10.5px]">
                              <dt className="font-mono text-slate-400">{key}</dt>
                              <dd className="break-all text-slate-600">{value}</dd>
                            </div>
                          ))}
                        </dl>
                      ) : null}
                    </li>
                  ))}
                </ol>

                <div className="mt-3 rounded-[8px] border border-line bg-panel p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.1em] text-brand-ring">
                    Questions to answer
                  </p>
                  <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[11.5px] text-slate-600">
                    {walkthrough.questions.map((question) => (
                      <li key={question}>{question}</li>
                    ))}
                  </ul>
                </div>

                <p className="mt-2 flex items-start gap-1.5 text-[11px] text-amber-400">
                  <BookOpenCheck size={12} className="mt-0.5 shrink-0" /> {walkthrough.safety}
                </p>

                {walkthrough.references.length > 0 ? (
                  <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10.5px]">
                    <span className="text-slate-500">References:</span>
                    {walkthrough.references.map((reference) => (
                      <span
                        key={reference}
                        className="max-w-[260px] truncate rounded-full border border-line px-1.5 py-0.5 font-mono text-slate-500"
                        title={reference}
                      >
                        {reference}
                      </span>
                    ))}
                  </div>
                ) : null}

                <div className="mt-3 flex items-center gap-2">
                  <Button size="sm" variant="secondary" onClick={loadExercises} disabled={exerciseBusy}>
                    {exerciseBusy ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
                    {exercises ? "Rebuild questions" : "Practice questions"}
                  </Button>
                  {exercises ? (
                    <span className="text-[11px] text-slate-500">
                      {exercises.filter((exercise) => checked[exercise.id] && isCorrect(exercise)).length}/
                      {exercises.length} correct
                    </span>
                  ) : null}
                </div>

                {exercises ? (
                  <div className="mt-3 space-y-2">
                    {exercises.map((exercise) => (
                      <ExerciseCard
                        key={exercise.id}
                        exercise={exercise}
                        selection={answers[exercise.id] ?? []}
                        revealed={Boolean(checked[exercise.id])}
                        correct={isCorrect(exercise)}
                        onSelect={chooseOption}
                        onCheck={() =>
                          setChecked((state) => ({ ...state, [exercise.id]: true }))
                        }
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </div>
      </Card>

      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[13px] font-semibold text-ink">Check catalogue</h2>
        <span className="text-[11px] text-slate-500">
          What each check looks for, why it matters and how to verify it by hand.
        </span>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {profileFilters.map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setProfile(value)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11.5px] font-medium capitalize transition",
              profile === value
                ? "border-brand-ring/40 bg-brand/15 text-brand-ring"
                : "border-line bg-panel text-slate-500 hover:text-ink",
            )}
          >
            {value === "all" ? `All ${checks?.length ?? 0}` : `${value} ${counts[value] ?? 0}`}
          </button>
        ))}
        <div className="relative ml-auto">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search checks…"
            className="h-8 w-[220px] rounded-[7px] border border-line bg-panel pl-8 pr-2 text-[12px] text-ink placeholder:text-slate-400"
          />
        </div>
      </div>

      {checks === null ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      ) : visible.length === 0 ? (
        <Notice tone="info">No checks match that filter.</Notice>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {visible.map((check) => (
            <Card key={check.id} className="flex flex-col p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-[13px] font-semibold leading-snug text-ink">{check.name}</p>
                  <p className="mt-0.5 font-mono text-[10.5px] text-slate-400">{check.id}</p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <SeverityBadge severity={check.severity} />
                  <ProfileBadge profile={check.profile} />
                </div>
              </div>
              <dl className="mt-3 space-y-2 text-[11.5px] leading-relaxed">
                <div>
                  <dt className="text-[10px] font-semibold uppercase tracking-[0.1em] text-brand-ring">What</dt>
                  <dd className="text-slate-600">{check.learning.what}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-semibold uppercase tracking-[0.1em] text-brand-ring">Why</dt>
                  <dd className="text-slate-600">{check.learning.why}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-semibold uppercase tracking-[0.1em] text-brand-ring">Verify</dt>
                  <dd className="text-slate-600">{check.learning.verify}</dd>
                </div>
              </dl>

              <div className="mt-auto flex items-center gap-2 pt-3">
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => runEducation(check.id)}
                  disabled={aiBusy === check.id}
                >
                  {aiBusy === check.id ? (
                    <Loader2 size={12} className="animate-spin" />
                  ) : (
                    <Sparkles size={12} />
                  )}
                  {notes[check.id] ? "Regenerate note" : "AI explain"}
                </Button>
                {notes[check.id] ? (
                  <Badge
                    tone={
                      notes[check.id].fallback
                        ? "bg-white/5 text-slate-500 border-line"
                        : "bg-brand/10 text-brand-ring border-brand-ring/25"
                    }
                  >
                    {notes[check.id].fallback ? "grounded fallback" : `AI · ${notes[check.id].provider}`}
                  </Badge>
                ) : null}
              </div>

              {notes[check.id] ? (
                <div className="mt-3 rounded-[8px] border border-brand-ring/25 bg-brand/[0.06] p-3">
                  {(() => {
                    const note = notes[check.id].payload as EducationNote;
                    return (
                      <>
                        <p className="text-[11.5px] leading-relaxed text-slate-600">
                          {note.plain_language}
                        </p>
                        <p className="mt-2 text-[11.5px] leading-relaxed text-slate-500">
                          <span className="font-semibold text-brand-ring">Why it matters: </span>
                          {note.why_it_matters}
                        </p>
                        <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-500">
                          <span className="font-semibold text-brand-ring">Verify manually: </span>
                          {note.how_to_verify}
                        </p>
                        {note.practice_tip ? (
                          <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-500">
                            <span className="font-semibold text-brand-ring">Practice: </span>
                            {note.practice_tip}
                          </p>
                        ) : null}
                      </>
                    );
                  })()}
                </div>
              ) : null}
            </Card>
          ))}
        </div>
      )}

      <Card className="mt-4">
        <CardHeader
          title="Analysis plugins"
          subtitle="Operator-installed plugins only see a scoped data payload — no network access, no credential store."
          action={
            <Badge tone="bg-white/5 text-slate-600 border-line">
              <Puzzle size={12} /> {plugins?.plugins.length ?? 0} loaded
            </Badge>
          }
        />
        {plugins === null ? (
          <div className="flex items-center gap-2 px-5 py-6 text-[12px] text-slate-400">
            <Loader2 size={14} className="animate-spin" /> Loading plugin catalogue…
          </div>
        ) : (
          <div className="px-5 py-4">
            <p className="flex items-start gap-1.5 text-[11.5px] text-slate-500">
              <BookOpenCheck size={13} className="mt-0.5 shrink-0 text-brand-ring" />
              Isolation contract: {plugins.isolation || "subprocess · scrubbed env · timeout · memory cap"}.
              Plugins return analysis-only findings; the parent re-scores every result and drops out-of-scope URLs.
            </p>
            {plugins.plugins.length === 0 ? (
              <p className="mt-3 text-[12px] text-slate-400">
                No plugin directories configured. Set <span className="font-mono">PLUGIN_DIRS</span> and reload the
                API to enable plugins.
              </p>
            ) : (
              <ul className="mt-3 divide-y divide-line rounded-[8px] border border-line">
                {plugins.plugins.map((plugin) => (
                  <li key={plugin.check_id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                    <span className="text-[12px] font-medium text-ink">{plugin.name}</span>
                    <span className="font-mono text-[10.5px] text-slate-400">{plugin.check_id}</span>
                    <SeverityBadge severity={plugin.severity} />
                    <ProfileBadge profile={plugin.profile} />
                    <span className="ml-auto text-[10.5px] text-slate-400">
                      {plugin.timeout_seconds}s · {plugin.memory_mb} MB
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {plugins.problems.length > 0 ? (
              <ul className="mt-3 space-y-1">
                {plugins.problems.map((problem) => (
                  <li key={problem} className="text-[11.5px] text-amber-300">
                    {problem}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        )}
      </Card>
    </div>
  );
}

function LessonRow({
  lesson,
  busy,
  onSelect,
}: {
  lesson: LearningLesson;
  busy: boolean;
  onSelect: (checkId: string, current: LearningStatus, target: LearningStatus) => void;
}) {
  return (
    <li className="py-2">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 text-[12px] font-medium text-ink">
            {lesson.status === "completed" ? (
              <CheckCircle2 size={12} className="shrink-0 text-emerald-400" />
            ) : null}
            {lesson.name}
          </p>
          <p className="mt-0.5 text-[10.5px] leading-relaxed text-slate-500">{lesson.objective}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <button
            type="button"
            disabled={busy}
            onClick={() => onSelect(lesson.id, lesson.status, "completed")}
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px] font-medium transition",
              lesson.status === "completed"
                ? statusStyles.completed
                : "border-line bg-panel text-slate-500 hover:text-ink",
            )}
          >
            {busy ? "…" : lesson.status === "completed" ? "Done ✓" : "Mark done"}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => onSelect(lesson.id, lesson.status, "in_progress")}
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px] font-medium transition",
              lesson.status === "in_progress"
                ? statusStyles.in_progress
                : "border-line bg-panel text-slate-500 hover:text-ink",
            )}
          >
            Studying
          </button>
        </div>
      </div>
    </li>
  );
}

function ExerciseCard({
  exercise,
  selection,
  revealed,
  correct,
  onSelect,
  onCheck,
}: {
  exercise: PracticeExercise;
  selection: string[];
  revealed: boolean;
  correct: boolean;
  onSelect: (exercise: PracticeExercise, option: string) => void;
  onCheck: () => void;
}) {
  return (
    <div className="rounded-[8px] border border-line bg-panel p-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11.5px] font-medium text-ink">{exercise.prompt}</p>
        <Badge tone="bg-white/5 text-slate-500 border-line">{exercise.type.replace("_", " ")}</Badge>
      </div>
      {exercise.multi ? (
        <p className="mt-1 text-[10px] text-slate-500">Select the items in order, then check your answer.</p>
      ) : null}
      <div className="mt-2 flex flex-wrap gap-1.5">
        {exercise.options.map((option) => {
          const chosen = selection.includes(option);
          const isAnswer = exercise.answer.includes(option);
          return (
            <button
              key={option}
              type="button"
              onClick={() => onSelect(exercise, option)}
              className={cn(
                "rounded-[6px] border px-2 py-1 text-left text-[10.5px] transition",
                revealed && isAnswer
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : revealed && chosen
                    ? "border-red-500/40 bg-red-500/10 text-red-300"
                    : chosen
                      ? "border-brand-ring/40 bg-brand/15 text-brand-ring"
                      : "border-line bg-panel text-slate-500 hover:text-ink",
              )}
            >
              {chosen && exercise.multi ? `${selection.indexOf(option) + 1}. ` : ""}
              {option}
            </button>
          );
        })}
      </div>
      {exercise.multi && !revealed ? (
        <Button
          size="sm"
          variant="ghost"
          className="mt-2"
          onClick={onCheck}
          disabled={selection.length === 0}
        >
          Check answer
        </Button>
      ) : null}
      {revealed ? (
        <p className={cn("mt-2 text-[11px]", correct ? "text-emerald-400" : "text-red-300")}>
          {correct ? "Correct. " : "Not yet. "}
          {exercise.explanation}
        </p>
      ) : null}
    </div>
  );
}
