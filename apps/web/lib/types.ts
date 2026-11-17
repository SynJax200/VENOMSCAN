export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type VerificationStatus = "suspected" | "verified" | "rejected";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ScanProfile = "passive" | "safe" | "active";

export interface User {
  id: string;
  email: string;
  name: string;
  role: "admin" | "user";
  created_at: string;
}

export interface AuthResponse {
  user: User;
  csrf_token: string;
}

export interface Verification {
  verified: boolean;
  method: string | null;
  verified_at: string | null;
  expires_at: string | null;
  token: string;
  dns_record_name: string;
  dns_record_value: string;
  well_known_url: string;
  attestation_required_text: string;
}

export interface Target {
  id: string;
  name: string;
  url: string;
  host: string;
  scope_notes: string;
  scan_count: number;
  created_at: string;
  verification: Verification;
}

export interface Finding {
  id: string;
  scan_id: string;
  check_id: string;
  title: string;
  category: string;
  severity: Severity;
  verification_status: VerificationStatus;
  confidence: number;
  risk_score: number;
  url: string;
  method: string;
  parameter: string | null;
  payload: string | null;
  description: string;
  impact: string;
  remediation: string;
  references: string[];
  cwe: string[];
  owasp: string[];
  cvss_score: number | null;
  cvss_vector: string | null;
  request_evidence: Record<string, unknown>;
  response_evidence: Record<string, unknown>;
  ai_summary: string;
  ai_priority: string;
  ai_false_positive_likelihood: number | null;
  occurrences: number;
  created_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  target_name: string;
  target_url: string;
  profile: ScanProfile;
  status: ScanStatus;
  phase: string;
  progress: number;
  stats: Record<string, number>;
  recon: Recon;
  summary: string;
  error: string;
  findings_total: number;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface DNSRecords {
  host?: string;
  records?: Record<string, string[]>;
  mail?: EmailAuth;
  error?: string | null;
}

export interface EmailAuth {
  spf?: string | null;
  dmarc?: {
    raw?: string;
    policy?: string | null;
    subdomain_policy?: string | null;
    percentage?: string | null;
    dkim_alignment?: string;
    spf_alignment?: string;
    report_uris?: string[];
    forensic_uris?: string[];
  } | null;
  dkim?: {
    selector: string;
    key_type: string;
    flags: string;
    key_length: number;
    revoked: boolean;
  }[];
}

export interface HistoryEntry {
  url: string;
  last_seen?: string | null;
  status?: string | null;
  kind?: string;
}

export interface HistoryInfo {
  domain?: string;
  urls?: HistoryEntry[];
  count?: number;
  source?: string;
  error?: string | null;
}

export interface ExposureInfo {
  address: string;
  source: string;
  ports: number[];
  hostnames: string[];
  organisation?: string | null;
  isp?: string | null;
  operating_system?: string | null;
  country?: string | null;
  tags: string[];
  vulns: string[];
  error?: string | null;
}

export interface NeighbourInfo {
  prefix?: string;
  queried?: number;
  hosts?: { address: string; ptr: string }[];
  count?: number;
  error?: string | null;
}

export interface TLSInfo {
  protocol?: string | null;
  cipher?: string | null;
  subject?: string | null;
  issuer?: string | null;
  not_before?: string | null;
  not_after?: string | null;
  days_to_expiry?: number | null;
  sans?: string[];
  verified?: boolean;
  error?: string | null;
}

export interface WAFInfo {
  detected?: boolean;
  summary?: string;
  vendors?: {
    name: string;
    category: string;
    confidence: number;
    evidence: string[];
  }[];
}

export interface IPAddressInfo {
  address: string;
  version: number;
  scope: string;
  ptr: string | null;
  asn?: string | null;
  as_name?: string | null;
  prefix?: string | null;
  country?: string | null;
}

export interface IPIntel {
  host?: string;
  addresses?: IPAddressInfo[];
  hosting?: string[];
  error?: string | null;
}

export interface SubdomainInfo {
  domain?: string;
  names?: string[];
  count?: number;
  wildcard?: boolean;
  source?: string;
  error?: string | null;
}

export interface WhoisInfo {
  domain?: string;
  registrar?: string | null;
  statuses?: string[];
  created?: string | null;
  updated?: string | null;
  expires?: string | null;
  nameservers?: string[];
  source?: string;
  error?: string | null;
}

export interface RobotsInfo {
  url?: string;
  allow?: string[];
  disallow?: string[];
  crawl_delay?: number | null;
  sitemaps?: string[];
}

export interface CrawlStats {
  pages?: number;
  links?: number;
  forms?: number;
  js_files?: number;
  js_endpoints?: number;
  probed?: number;
  api_specs?: number;
  api_endpoints?: number;
  robots_found?: boolean;
  sitemap_urls?: number;
  stopped?: string | null;
}

export interface ApiDocument {
  url: string;
  title?: string;
  version?: string;
  spec_version?: string;
  paths?: number;
  operations?: number;
  servers?: string[];
  security_schemes?: string[];
  global_security?: boolean;
  declared_auth?: boolean;
}

export interface ApiSurface {
  documents?: ApiDocument[];
  endpoint_count?: number;
}

export interface DirStats {
  probed: number;
  found: number;
  paths: string[];
  soft_404: boolean;
  stopped: string | null;
  warnings: number;
}

export interface SourceMapRef {
  url: string;
  same_origin: boolean;
}

export interface JsIntel {
  scripts?: number;
  api_calls?: number;
  post_calls?: number;
  source_maps?: SourceMapRef[];
  graphql_endpoints?: string[];
  third_party_hosts?: string[];
  sensitive_paths?: string[];
  parameters?: string[];
  methods?: Record<string, string>;
}

export interface EndpointCluster {
  template: string;
  count: number;
  methods: string[];
  sources: string[];
  parameters: string[];
  samples: string[];
  api_like: boolean;
}

export interface EndpointIntel {
  cluster_count: number;
  endpoint_count: number;
  templated: number;
  api_clusters: number;
  clusters: EndpointCluster[];
}

export interface ApiSpecIntel {
  documents: number;
  routes: number;
  operations: number;
  public_write_count: number;
  public_writes: { path: string; method: string }[];
  public_reads: number;
  api_key_query_schemes: string[];
  oauth_implicit: string[];
  cross_origin_servers: string[];
  deprecated_count: number;
  operations_by_method: Record<string, number>;
}

export interface JwtTokenIntel {
  fingerprint: string;
  prefix: string;
  alg: string;
  claims: string[];
  lifetime_days: number | null;
  flags: string[];
  location: string;
  source: string;
}

export interface GraphqlIntel {
  candidates: string[];
  probed: number;
  confirmed: string[];
  introspection: boolean;
  ide: boolean;
  type_count?: number;
  object_count?: number;
  mutation_available?: boolean;
  sample_types?: string[];
}

export interface ApiIntel {
  spec?: ApiSpecIntel;
  jwt?: { tokens?: JwtTokenIntel[] };
  graphql?: GraphqlIntel;
}

export interface SurfaceHints {
  query_parameters?: string[];
  form_parameters?: string[];
  cookies?: string[];
  header_candidates?: string[];
}

export interface VerificationSummary {
  verified?: number;
  suspected?: number;
  rejected?: number;
  downgraded?: number;
}

export interface Recon {
  dns?: DNSRecords;
  ip_intel?: IPIntel;
  tls?: TLSInfo;
  waf?: WAFInfo;
  robots?: RobotsInfo;
  subdomains?: SubdomainInfo;
  whois?: WhoisInfo;
  history?: HistoryInfo;
  exposure?: ExposureInfo[];
  neighbours?: NeighbourInfo;
  crawl?: CrawlStats;
  js_intel?: JsIntel;
  endpoint_intel?: EndpointIntel;
  dirs?: DirStats;
  surface?: SurfaceHints;
  api?: ApiSurface;
  api_intel?: ApiIntel;
  verification?: VerificationSummary;
}

export interface Technology {
  name: string;
  version: string | null;
  category: string;
  confidence: number;
}

export type EndpointState = "live" | "unverified" | "archived";

export interface Endpoint {
  url: string;
  method: string;
  source: string;
  status_code: number | null;
  content_type: string | null;
  depth: number;
  parameters: string[];
  state?: EndpointState;
}

export interface ScanDetail extends Scan {
  findings: Finding[];
  technologies: Technology[];
  endpoints: Endpoint[];
}

export interface ScanEvent {
  id: number;
  phase: string;
  type: string;
  message: string;
  progress: number;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface CheckResultRow {
  check_id: string;
  name: string;
  status: "running" | "completed" | "failed" | "skipped" | "cancelled";
  findings: number;
  duration_ms: number;
  error: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface DashboardScan {
  id: string;
  target_name: string;
  target_url: string;
  profile: ScanProfile;
  status: ScanStatus;
  progress: number;
  findings_total: number;
  created_at: string;
}

export interface DashboardTarget {
  id: string;
  name: string;
  url: string;
  scans: number;
  findings: number;
  last_scan_at: string | null;
  last_status: string;
}

export interface SplitSlice {
  name: string;
  count: number;
}

export interface Dashboard {
  total_scans: number;
  completed_scans: number;
  active_scans: number;
  total_findings: number;
  severity: SeverityCounts;
  recent_scans: DashboardScan[];
  technologies: { name: string; count: number }[];
  targets: DashboardTarget[];
  by_check: SplitSlice[];
  by_owasp: SplitSlice[];
  insights: string[];
}

export interface AuditEvent {
  id: number;
  action: string;
  target_type: string;
  target_id: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface CheckLearning {
  what: string;
  why: string;
  verify: string;
}

export interface CheckInfo {
  id: string;
  name: string;
  category: string;
  profile: ScanProfile;
  severity: Severity;
  learning: CheckLearning;
}

export interface ScanDefaults {
  profile: ScanProfile;
}

export interface WorkspaceSettings {
  scan_defaults: ScanDefaults;
  disabled_checks: string[];
  updated_at: string | null;
}

export interface Credential {
  id: string;
  target_id: string | null;
  label: string;
  role: string;
  identity: string;
  header_names: string[];
  created_at: string;
}

export interface AiSettings {
  provider: "openai_compat" | "anthropic" | "ollama";
  model: string;
  base_url: string;
  key_configured: boolean;
  updated_at: string | null;
}

export interface AiProviderTest {
  configured: boolean;
  reachable: boolean;
  provider: string;
  model: string;
  latency_ms: number;
  error: string;
}

export interface AiAnalysis {
  id: string;
  kind: string;
  provider: string;
  model: string;
  prompt_version: string;
  grounded: boolean;
  fallback: boolean;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AssistantAnswer {
  answer: string;
  grounded: boolean;
  fallback: boolean;
  provider: string;
  model: string;
  prompt_version: string;
  refused: boolean;
  references: string[];
}

export type ReportFormat = "json" | "markdown" | "html" | "pdf";

export interface Report {
  id: string;
  scan_id: string;
  format: ReportFormat;
  title: string;
  filename: string;
  sha256: string;
  size: number;
  created_at: string;
  expires_at: string;
  download_url: string;
  preview_url: string;
  signed_url: string;
}

export interface CompareFinding {
  id: string;
  check_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  url: string;
  verification_status: VerificationStatus;
}

export interface ScanCompare {
  base_scan_id: string;
  other_scan_id: string;
  base_label: string;
  other_label: string;
  new: CompareFinding[];
  fixed: CompareFinding[];
  persisting: CompareFinding[];
  counts: { new: number; fixed: number; persisting: number };
}

export interface IntelCve {
  id: string;
  severity: Severity;
  cvss: number | null;
  summary: string;
  cwe: string[];
  refs: string[];
}

export interface IntelMatch {
  technology: string;
  version: string | null;
  product: string;
  version_unknown: boolean;
  cve: IntelCve;
}

export interface IntelReport {
  snapshot_version: string;
  source: string;
  matches: IntelMatch[];
}

export interface NucleiStatus {
  enabled: boolean;
  configured: boolean;
  binary_present: boolean;
  templates_present: boolean;
  severities: string[];
  rate_limit: number;
  timeout: number;
}

export interface IntegrationStatus {
  nuclei: NucleiStatus;
  burp_import: boolean;
  burp_export: boolean;
  upstream_proxy: boolean;
  plugin_dirs: string[];
}

export interface BurpImportResult {
  scan_id: string;
  imported: number;
  skipped: number;
  out_of_scope: number;
}

export interface PluginInfo {
  check_id: string;
  name: string;
  category: string;
  severity: Severity;
  profile: string;
  timeout_seconds: number;
  memory_mb: number;
  file: string;
}

export interface PluginCatalog {
  plugins: PluginInfo[];
  problems: string[];
  isolation: string;
}

export type LearningStatus = "not_started" | "in_progress" | "completed";

export interface LearningLesson {
  id: string;
  name: string;
  category: string;
  profile: ScanProfile;
  severity: Severity;
  objective: string;
  what: string;
  why: string;
  verify: string;
  status: LearningStatus;
  updated_at: string | null;
}

export interface LearningTrack {
  id: string;
  title: string;
  level: "beginner" | "intermediate" | "advanced";
  focus: string;
  outcome: string;
  scan_profile: ScanProfile;
  consent: string;
  check_ids: string[];
  lessons: LearningLesson[];
  completed: number;
  total: number;
  percent: number;
}

export interface LearningPaths {
  tracks: LearningTrack[];
  check_count: number;
  completed: number;
  in_progress: number;
  percent: number;
}

export interface EndpointLearningLesson {
  finding_id: string;
  check_id: string;
  title: string;
  severity: Severity;
  verification_status: string;
  risk_score: number;
  what: string;
  why: string;
  verify: string;
}

export interface EndpointLearningEntry {
  url: string;
  method: string;
  source: string;
  state: EndpointState;
  status_code: number | null;
  finding_count: number;
  lessons: EndpointLearningLesson[];
}

export interface ScanEndpointLearning {
  scan_id: string;
  target_url: string;
  endpoint_count: number;
  with_findings: number;
  endpoints: EndpointLearningEntry[];
}

export interface PracticeFinding {
  id: string;
  scan_id: string;
  check_id: string;
  title: string;
  category: string;
  severity: Severity;
  verification_status: string;
  confidence: number;
  risk_score: number;
  url: string;
  method: string;
  created_at: string;
}

export interface WalkthroughStep {
  key: string;
  title: string;
  detail: string;
  evidence: Record<string, string>;
}

export interface Walkthrough {
  finding_id: string;
  check_id: string;
  title: string;
  severity: Severity;
  url: string;
  method: string;
  verification_status: string;
  confidence: number | null;
  risk_score: number | null;
  learning: Partial<CheckLearning>;
  steps: WalkthroughStep[];
  questions: string[];
  safety: string;
  references: string[];
}

export interface PracticeExercise {
  id: string;
  type: "evidence_read" | "verify_path" | "step_order" | "risk_triage";
  prompt: string;
  options: string[];
  answer: string[];
  multi: boolean;
  explanation: string;
}
