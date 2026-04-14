import ssl
import socket
import json
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

OUTDATED_VERSIONS = {"TLSv1", "TLSv1.1"}


def format_name(name):
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def get_cert_dates(cert):
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return not_before, not_after


def matches_name(hostname, pattern):
    if pattern.startswith("*."):
        # Wildcard: split both on dots, must have same number of parts
        pattern_parts = pattern.split(".")
        hostname_parts = hostname.split(".")
        if len(hostname_parts) != len(pattern_parts):
            return False
        # Compare all parts except the first (wildcard)
        for p, h in zip(pattern_parts[1:], hostname_parts[1:]):
            if p.lower() != h.lower():
                return False
        return True
    else:
        return hostname.lower() == pattern.lower()


def hostname_match(hostname, cn, sans):
    # Check SANs first
    for san in sans:
        if matches_name(hostname, san):
            return True
    # Fall back to CN
    if cn and matches_name(hostname, cn):
        return True
    return False


def analyze_endpoint(host, port):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # For TLS 1.0 endpoint, try to allow older versions
        if int(port) == 1010:
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass

        sock = socket.create_connection((host, int(port)), timeout=10)
        ssl_sock = ctx.wrap_socket(sock, server_hostname=host)

        tls_version = ssl_sock.version()
        cipher_suite = ssl_sock.cipher()[0]

        der_bytes = ssl_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der_bytes)

        # Extract CN
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else None

        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        # Extract dates
        not_before, not_after = get_cert_dates(cert)

        # Build certificate chain (leaf only)
        certificate_chain = [
            {
                "subject": format_name(cert.subject),
                "issuer": format_name(cert.issuer),
            }
        ]

        ssl_sock.close()
        sock.close()

        # Detection rules
        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now > not_after
        self_signed = cert.subject == cert.issuer
        host_match = hostname_match(host, cn, sans)
        outdated_tls = tls_version in OUTDATED_VERSIONS

        issues = []
        if is_expired:
            issues.append("Expired certificate")
        if self_signed:
            issues.append("Self-signed certificate")
        if not host_match:
            issues.append("Hostname mismatch")
        if outdated_tls:
            issues.append("Outdated TLS version")

        return {
            "target": f"{host}:{port}",
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "certificate_chain": certificate_chain,
            "leaf_certificate": {
                "subject_cn": cn,
                "subject_alt_names": sans,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "is_expired": is_expired,
                "hostname_match": host_match,
            },
            "issues": issues,
        }

    except Exception as e:
        return {"target": f"{host}:{port}", "error": str(e)}


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tls_analyzer.py <targets_file>", file=sys.stderr)
        sys.exit(1)

    targets_file = sys.argv[1]
    with open(targets_file) as f:
        lines = [line.strip() for line in f if line.strip()]

    results = []
    for line in lines:
        host, port = line.rsplit(":", 1)
        result = analyze_endpoint(host, int(port))
        results.append(result)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
