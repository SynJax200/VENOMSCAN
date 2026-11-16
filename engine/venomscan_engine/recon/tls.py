from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class TLSInfo:
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_to_expiry: int | None = None
    sans: list[str] = field(default_factory=list)
    verified: bool = False
    error: str | None = None


def _cert_fields(der: bytes) -> dict:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    try:
        sans = [
            str(name.value)
            for name in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        ]
    except Exception:
        sans = []
    not_after = cert.not_valid_after_utc
    days = (not_after - datetime.now(UTC)).days
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": days,
        "sans": sans,
    }


def _handshake(
    host: str, port: int, timeout: float, *, verify: bool
) -> tuple[dict, str | None, str | None]:
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            cipher = tls_sock.cipher()[0] if tls_sock.cipher() else None
            details = _cert_fields(der) if der else {}
            return details, tls_sock.version(), cipher


def probe_tls(host: str, port: int = 443, timeout: float = 8.0) -> TLSInfo:
    try:
        details, protocol, cipher = _handshake(host, port, timeout, verify=True)
        return TLSInfo(protocol=protocol, cipher=cipher, verified=True, **details)
    except ssl.SSLCertVerificationError as exc:
        verification_error = getattr(exc, "verify_message", None) or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return TLSInfo(error=str(exc)[:300])

    try:
        details, protocol, cipher = _handshake(host, port, timeout, verify=False)
        return TLSInfo(
            protocol=protocol,
            cipher=cipher,
            verified=False,
            error=verification_error,
            **details,
        )
    except (OSError, ssl.SSLError) as exc:
        return TLSInfo(error=str(exc)[:300])


async def probe_tls_async(host: str, port: int = 443, timeout: float = 8.0) -> TLSInfo:  # noqa: ASYNC109
    return await asyncio.to_thread(probe_tls, host, port, timeout)
