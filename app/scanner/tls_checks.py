"""TLS / certificate facts: one verified handshake, one unverified (to read a broken
certificate), and at most two short legacy-protocol probes. No cipher enumeration."""
from __future__ import annotations

import datetime as dt
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _key_type(key) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(key).__name__


def parse_certificate(der: bytes, now: dt.datetime | None = None) -> dict:
    cert = x509.load_der_x509_certificate(der)
    now = now or dt.datetime.now(dt.timezone.utc)
    not_after = cert.not_valid_after_utc
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "sans": sans[:50],
        "self_signed": cert.issuer == cert.subject,
        "signature_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
        "key_type": _key_type(key),
        "key_size": getattr(key, "key_size", None),
    }


def _handshake(ip: str, host: str, ctx: ssl.SSLContext, timeout: float):
    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version(), tls.cipher(), tls.getpeercert(binary_form=True)


def _probe_legacy(ip: str, host: str, version: ssl.TLSVersion, timeout: float) -> str:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "unknown"
    try:
        _handshake(ip, host, ctx, timeout)
        return "supported"
    except ssl.SSLError as exc:
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "NO_CIPHERS" in str(exc).upper():
            return "unknown"  # our local OpenSSL cannot speak it; do not guess
        return "not_supported"
    except OSError:
        return "unknown"


def collect_tls(host: str, ip: str | None, timeout: float = 6.0, probe_legacy: bool = True) -> dict:
    facts: dict = {"host": host, "ip": ip, "available": False}
    if not ip:
        facts["error"] = "no_public_ip"
        return facts
    try:
        version, cipher, der = _handshake(ip, host, ssl.create_default_context(), timeout)
        facts.update(available=True, verified=True, version=version, cipher=cipher[0] if cipher else None)
    except ssl.SSLCertVerificationError as exc:
        facts.update(available=True, verified=False,
                     verify_error=exc.verify_message or str(exc)[:200], verify_code=exc.verify_code)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            version, cipher, der = _handshake(ip, host, ctx, timeout)
            facts.update(version=version, cipher=cipher[0] if cipher else None)
        except (OSError, ssl.SSLError) as exc2:
            facts["error"] = type(exc2).__name__
            return facts
    except ssl.SSLError as exc:
        facts.update(available=False, error="tls_handshake_failed", detail=str(exc)[:200])
        return facts
    except OSError as exc:
        facts.update(available=False, error="connect_failed", detail=type(exc).__name__)
        return facts
    if der:
        facts["certificate"] = parse_certificate(der)
    if probe_legacy:
        facts["legacy"] = {
            "TLSv1": _probe_legacy(ip, host, ssl.TLSVersion.TLSv1, timeout),
            "TLSv1.1": _probe_legacy(ip, host, ssl.TLSVersion.TLSv1_1, timeout),
        }
    return facts
