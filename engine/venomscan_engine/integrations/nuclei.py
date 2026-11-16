from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.safety.redact import redact_text
from venomscan_engine.safety.scope import Scope, ScopeViolation

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_MAX_OUTPUT_BYTES = 2_000_000
_SYSTEM_ENV = {
    "PATH",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "TMP",
    "TEMP",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
}


class NucleiError(RuntimeError):
    pass


@dataclass(frozen=True)
class NucleiConfig:
    """Operator-controlled Nuclei integration. Disabled unless explicitly configured."""

    binary: str
    templates: str = ""
    severities: tuple[str, ...] = ("info", "low", "medium")
    rate_limit: int = 10
    timeout: int = 60
    max_findings: int = 100
    proxy_url: str = ""
    extra_allowed_hosts: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        path = Path(self.binary)
        if not path.is_absolute() or not path.is_file():
            raise NucleiError("nuclei binary must be an absolute path to an existing file")
        if not os.access(path, os.X_OK):
            raise NucleiError("nuclei binary is not executable")
        if self.templates:
            template_path = Path(self.templates)
            if not template_path.is_absolute() or not template_path.is_dir():
                raise NucleiError("nuclei templates must be an absolute directory")
        unknown = set(self.severities) - _ALLOWED_SEVERITIES
        if unknown or not self.severities:
            raise NucleiError(f"unsupported nuclei severities: {sorted(unknown)}")
        if not 1 <= self.rate_limit <= 20:
            raise NucleiError("nuclei rate limit must be between 1 and 20 requests/second")
        if not 5 <= self.timeout <= 180:
            raise NucleiError("nuclei timeout must be between 5 and 180 seconds")
        if not 1 <= self.max_findings <= 500:
            raise NucleiError("nuclei finding cap must be between 1 and 500")

    def argv(self, target_url: str) -> list[str]:
        args = [
            self.binary,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-severity",
            ",".join(self.severities),
            "-rate-limit",
            str(self.rate_limit),
            "-timeout",
            "5",
            "-max-host-error",
            "2",
            "-target",
            target_url,
        ]
        if self.templates:
            args += ["-t", self.templates]
        if self.proxy_url:
            args += ["-proxy", self.proxy_url]
        return args

    def clean_env(self) -> dict[str, str]:
        """Plugins and external binaries never inherit platform secrets."""
        allowed = _SYSTEM_ENV
        return {key: value for key, value in os.environ.items() if key in allowed}


def _severity(value: str) -> Severity:
    normalized = (value or "").lower()
    return Severity(normalized) if normalized in _ALLOWED_SEVERITIES else Severity.INFO


def _finding_from_template(payload: dict, scope: Scope) -> Finding | None:
    info = payload.get("info") or {}
    url = payload.get("matched-at") or payload.get("host") or ""
    if not url:
        return None
    try:
        scope.check(url)
    except ScopeViolation:
        return None
    classification = info.get("classification") or {}
    template_id = str(payload.get("template-id") or "unknown")
    protocol = str(payload.get("type") or "http").lower()
    # Nuclei reports protocol families ("http", "dns", ...), not the verb; the
    # bundled HTTP templates issue GETs.
    method = "GET" if protocol in {"http", "https"} else protocol.upper()
    check_id = "nuclei." + "".join(
        char if char.isalnum() or char in "._-" else "_" for char in template_id.lower()
    )
    description = str(info.get("description") or f"Nuclei template {template_id} matched.")
    evidence = {
        "matcher": payload.get("matcher-name") or "",
        "template": template_id,
        "request": redact_text(str(payload.get("request") or ""), limit=1500),
        "response": redact_text(str(payload.get("response") or ""), limit=1500),
    }
    cwe = classification.get("cwe-id") or []
    if isinstance(cwe, str):
        cwe = [cwe]
    references = info.get("reference") or []
    if isinstance(references, str):
        references = [references]
    finding = Finding(
        check_id=check_id,
        title=str(info.get("name") or template_id),
        category="nuclei",
        severity=_severity(str(info.get("severity") or "info")),
        confidence=7,
        verification_status=VerificationStatus.SUSPECTED,
        url=url,
        method=method,
        payload=payload.get("matcher-name"),
        description=description,
        impact=(
            "Nuclei matched this template against the target. Treat the match as a lead: "
            "review the captured request/response before acting on it."
        ),
        remediation=str(
            info.get("remediation")
            or "Follow the template guidance and the linked references, then re-test."
        ),
        references=[str(ref) for ref in references][:10],
        cwe=[str(item) for item in cwe][:5],
        cvss_score=classification.get("cvss-score"),
        cvss_vector=classification.get("cvss-metrics"),
        request_evidence=evidence,
        response_evidence={"url": url},
    )
    return finding.finalize()


async def _read_capped(stream: asyncio.StreamReader, limit: int = _MAX_OUTPUT_BYTES) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            chunks.append(chunk[: limit - (total - len(chunk))])
            break
        chunks.append(chunk)
    return b"".join(chunks)


def parse_nuclei_output(data: bytes, scope: Scope, *, limit: int = 100) -> list[Finding]:
    findings: list[Finding] = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = _finding_from_template(payload, scope)
        if finding is None:
            continue
        findings.append(finding)
        if len(findings) >= limit:
            break
    return findings


async def run_nuclei(config: NucleiConfig, target_url: str, scope: Scope) -> list[Finding]:
    """Run an operator-installed Nuclei binary with hard caps and scope re-validation."""
    config.validate()
    process = await asyncio.create_subprocess_exec(
        *config.argv(target_url),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=config.clean_env(),
    )
    try:
        stdout, _stderr = await asyncio.wait_for(
            asyncio.gather(_read_capped(process.stdout), _read_capped(process.stderr)),
            timeout=config.timeout,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise NucleiError(f"nuclei exceeded {config.timeout}s and was stopped") from exc
    await process.wait()
    return parse_nuclei_output(stdout, scope, limit=config.max_findings)
