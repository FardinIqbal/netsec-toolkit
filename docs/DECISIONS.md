# Architectural Decision Records

Each entry documents a non-obvious engineering choice, its alternatives, and why I picked what I picked.

---

## ADR 1: Three independent scripts instead of a unified CLI

**Status:** accepted

**Context:**
The toolkit has three logically distinct functions: ping, port scan, TLS analysis. Two options:

1. **One unified CLI** with subcommands (e.g., `netsec ping`, `netsec scan`, `netsec tls`).
2. **Three independent scripts** (this design): `scapy_ping.py`, `scapy_syn.py`, `tls_analyzer.py`, plus `generate_report.py` to orchestrate.

**Decision:**
Independent scripts.

**Consequences:**

- Pro: each script is small and focused. Easier to read in isolation.
- Pro: each script can be invoked independently. No need to remember subcommand syntax.
- Pro: simpler to test (each script can be exercised on its own).
- Con: more entry points to document.
- Con: shared utilities would have to be extracted to a common module if the codebase grew.

For a small toolkit, independent scripts are the right scope. If the codebase grew to include more tools or shared logic, consolidation into a unified CLI would make sense.

---

## ADR 2: Scapy for packet manipulation

**Status:** accepted

**Context:**
Sending and receiving raw network packets in Python. Two options:

1. **Scapy** (this design): the de-facto standard for packet manipulation in Python.
2. **Raw socket programming with `socket` and `struct`**: more code, but no external dependency.

**Decision:**
Scapy.

**Consequences:**

- Pro: layer abstraction is excellent. `IP/ICMP/Raw(b"...")` reads naturally.
- Pro: built-in `traceroute()`, `sr1()`, `sniff()` save dozens of lines per tool.
- Pro: pcap reading and writing for testing.
- Con: external dependency (`scapy` is a heavy install).
- Con: requires root for raw socket access (same as raw `socket`).

For tools that work with packets at this level, Scapy is the right choice. The dependency cost is justified.

---

## ADR 3: cryptography library over pyOpenSSL

**Status:** accepted

**Context:**
Parsing X.509 certificates in Python. Two options:

1. **`cryptography`** (this design): modern, actively maintained, the recommended library.
2. **`pyOpenSSL`**: older, wraps OpenSSL's C library, considered legacy.

**Decision:**
`cryptography`.

**Consequences:**

- Pro: pure-Python where possible, OpenSSL backend where needed. Easier to install and ship.
- Pro: clean API: `x509.load_der_x509_certificate(der_bytes)` returns an object with named attributes.
- Pro: actively developed, fast security updates.
- Con: API differs from pyOpenSSL, so existing pyOpenSSL examples need translation.

Modern Python crypto work uses `cryptography`. `pyOpenSSL` is legacy.

---

## ADR 4: SYN scan over connect scan

**Status:** accepted

**Context:**
TCP port scanning. Two options:

1. **SYN scan** (this design): send SYN, look at response, do not complete handshake.
2. **Connect scan**: complete the full TCP handshake (SYN, SYN+ACK, ACK).

**Decision:**
SYN.

**Consequences:**

- Pro: faster. No handshake completion means no extra round-trip.
- Pro: less likely to be logged by the target. Many application-layer servers only log completed connections.
- Pro: matches `nmap`'s default for the same reasons.
- Con: requires raw socket access (root).
- Con: a non-privileged user cannot run a SYN scan.

For privileged use (the intended deployment), SYN is the right choice. For non-privileged use, the script could fall back to a connect scan.

---

## ADR 5: Disable cert verification during analysis

**Status:** accepted (essential for the use case)

**Context:**
The TLS analyzer needs to inspect certificates that may be invalid (expired, self-signed, wrong hostname). The default Python `ssl` module rejects invalid certs and refuses to connect.

**Decision:**
Disable verification.

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

**Consequences:**

- Pro: the analyzer can inspect any cert, including the bad ones we want to flag.
- Pro: no special-case handling for connections that the default context would reject.
- Con: this is dangerous in a production HTTP client. The analyzer is a special-purpose tool; a normal client would never disable verification.

This is the entire point of an analyzer. A normal HTTP client must verify; an analyzer must not.

---

## ADR 6: Markdown report instead of HTML or PDF directly

**Status:** accepted

**Context:**
`generate_report.py` produces a unified report. Output format options:

1. **Markdown** (this design): plain text with structured sections.
2. **HTML**: directly viewable in a browser.
3. **PDF**: ready to share without rendering.

**Decision:**
Markdown.

**Consequences:**

- Pro: human-readable in any text editor.
- Pro: convertible to HTML or PDF via standard tools (`pandoc`, `weasyprint`).
- Pro: version-controllable. Diffs against previous reports are useful.
- Con: not directly printable. The user must run the conversion step for HTML or PDF.

Markdown is the universal source format. Anyone who wants HTML or PDF can convert with one command.
