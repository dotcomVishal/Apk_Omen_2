"""
apk_extractor.py
────────────────────────────────────────────────────────────────────────────────
Core APK Security Analysis — Static Extraction Pipeline
Author  : Senior Python Backend Security Engineer
Purpose : Decompile an APK, parse its manifest, hunt for hardcoded secrets,
          and emit a structured JSON-ready dict for downstream LLM reasoning.

Designed to be consumed by a FastAPI route via `asyncio.to_thread()`.
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

# ──────────────────────────────────────────────────────────────────────────────
# Typed output contracts
# ──────────────────────────────────────────────────────────────────────────────

class ExportedComponent(TypedDict):
    name: str
    type: str          # "activity" | "service" | "receiver" | "provider"
    intent_filters: list[str]


class FoundSecret(TypedDict):
    file: str
    line_number: int
    rule_name: str
    match_preview: str            # truncated / partially redacted
    entropy: float                # Shannon entropy of the raw match string
    confidence: str               # "HIGH" | "LIKELY_FALSE_POSITIVE"


class InsecurePattern(TypedDict):
    """
    A match from INSECURE_CODE_RULES.

    Intentionally separate from FoundSecret so the LLM prompt can treat
    'leaked credentials' and 'dangerous API usage' as distinct finding classes.
    Entropy is always -1.0 because structural code patterns are not evaluated
    against the entropy gate.
    """
    file: str
    line_number: int
    rule_name: str
    category: str       # "crypto" | "webview" | "storage" | "cleartext_traffic"
    match_preview: str  # full matched snippet, not redacted — it's not a secret
    confidence: str     # always "HIGH" for insecure patterns


class ExtractionReport(TypedDict):
    apk_path: str
    package_name: str
    min_sdk: str
    target_sdk: str
    permissions: list[str]
    dangerous_permissions: list[str]
    exported_components: list[ExportedComponent]
    secrets: list[FoundSecret]
    endpoints: list[str]                          # deduplicated URLs + IPs
    insecure_code_patterns: list[InsecurePattern]
    errors: list[str]


# ──────────────────────────────────────────────────────────────────────────────
# Configuration / rule sets
# ──────────────────────────────────────────────────────────────────────────────

DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        # Location
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        # Telephony / SMS
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        # Contacts / Calendar
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        # Storage
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        # Camera / Microphone
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        # Device identifiers
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        # Biometrics / Body sensors
        "android.permission.USE_BIOMETRIC",
        "android.permission.BODY_SENSORS",
        # Other high-risk
        "android.permission.GET_ACCOUNTS",
        "android.permission.USE_CREDENTIALS",
        "android.permission.AUTHENTICATE_ACCOUNTS",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
    }
)

# Secret-hunting regex rules: (rule_name, compiled_pattern)
SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    # Google / Firebase
    (
        "google_api_key",
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    ),
    (
        "google_oauth_client_id",
        re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    ),
    (
        "firebase_url",
        re.compile(r'https?://[a-z0-9\-]+\.firebaseio\.com'),
    ),
    # AWS
    (
        "aws_access_key_id",
        re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])'),
    ),
    (
        "aws_secret_access_key",
        re.compile(
            r'(?i)aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
        ),
    ),
    # Generic password assignments
    (
        "generic_password",
        re.compile(
            r'(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*["\']([^"\']{6,})["\']'
        ),
    ),
    # Generic API key / token assignments
    (
        "generic_api_key",
        re.compile(
            r'(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9\-_.]{16,})["\']'
        ),
    ),
    # Private keys (PEM headers)
    (
        "private_key_header",
        re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    ),
    # Slack / Discord webhooks
    (
        "slack_webhook",
        re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+'),
    ),
    (
        "discord_webhook",
        re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+'),
    ),
    # JWT (loose header detection)
    (
        "jwt_token",
        re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
    ),
    # Stripe keys
    (
        "stripe_key",
        re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'),
    ),
]

# ──────────────────────────────────────────────────────────────────────────────
# Insecure code pattern rules
# ──────────────────────────────────────────────────────────────────────────────
# Schema: (rule_name, category, compiled_pattern)
# These rules match dangerous API calls and code constructs — NOT secrets.
# They NEVER pass through the entropy gate; a regex match alone is HIGH confidence.

INSECURE_CODE_RULES: list[tuple[str, str, re.Pattern[str]]] = [

    # ── Weak / broken cryptography ────────────────────────────────────────────
    (
        "aes_ecb_mode",
        "crypto",
        # ECB mode is deterministic and leaks plaintext structure.
        re.compile(r'AES/ECB/(?:PKCS5Padding|NoPadding|PKCS7Padding)', re.IGNORECASE),
    ),
    (
        "des_cipher",
        "crypto",
        # DES has a 56-bit key — brute-forceable in hours on modern hardware.
        re.compile(r'\bDES(?:ede)?\s*/[A-Z]+/[A-Z]+|\bgetInstance\s*\(\s*["\']DES["\']', re.IGNORECASE),
    ),
    (
        "md5_digest",
        "crypto",
        # MD5 is cryptographically broken for integrity and password hashing.
        re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)', re.IGNORECASE),
    ),
    (
        "sha1_digest",
        "crypto",
        # SHA-1 is deprecated for collision resistance (SHAttered attack, 2017).
        re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']\s*\)', re.IGNORECASE),
    ),
    (
        "rsa_no_oaep",
        "crypto",
        # RSA without OAEP padding is vulnerable to padding oracle attacks.
        re.compile(r'RSA/(?:ECB|NONE)/(?:PKCS1Padding|NoPadding)', re.IGNORECASE),
    ),
    (
        "static_iv",
        "crypto",
        # Hardcoded / zero IVs destroy semantic security of CBC/CTR modes.
        re.compile(r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\d+\s*\]\s*\)', re.IGNORECASE),
    ),

    # ── Insecure WebView configuration ────────────────────────────────────────
    (
        "webview_javascript_enabled",
        "webview",
        # Enables JS execution — attack surface for XSS if content is untrusted.
        re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)', re.IGNORECASE),
    ),
    (
        "webview_javascript_interface",
        "webview",
        # Exposes Java objects to JS — RCE if the WebView loads untrusted URLs.
        re.compile(r'addJavascriptInterface\s*\(', re.IGNORECASE),
    ),
    (
        "webview_allow_file_access",
        "webview",
        # Allows file:// URIs — may leak local app data to malicious pages.
        re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)', re.IGNORECASE),
    ),
    (
        "webview_allow_universal_file_access",
        "webview",
        # Allows cross-origin file:// reads — severe data exfiltration risk.
        re.compile(r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', re.IGNORECASE),
    ),

    # ── Insecure data storage ─────────────────────────────────────────────────
    (
        "world_readable_file",
        "storage",
        # MODE_WORLD_READABLE was deprecated in API 17; allows any app to read.
        re.compile(r'MODE_WORLD_READABLE', re.IGNORECASE),
    ),
    (
        "world_writeable_file",
        "storage",
        # MODE_WORLD_WRITEABLE was deprecated in API 17; allows any app to write.
        re.compile(r'MODE_WORLD_WRITEABLE', re.IGNORECASE),
    ),
    (
        "shared_prefs_world_readable",
        "storage",
        re.compile(r'getSharedPreferences\s*\([^)]+MODE_WORLD_READABLE', re.IGNORECASE),
    ),
    (
        "external_storage_write",
        "storage",
        # Writing sensitive data to external storage exposes it to other apps.
        re.compile(r'getExternalStorageDirectory\s*\(\s*\)|getExternalFilesDir\s*\(', re.IGNORECASE),
    ),

    # ── Cleartext / insecure network traffic ─────────────────────────────────
    (
        "cleartext_http_url",
        "cleartext_traffic",
        # Any http:// URL in code is a cleartext traffic signal (not HTTPS).
        # Exclude localhost / 127.0.0.1 to avoid dev-only false positives.
        re.compile(r'http://(?!(?:localhost|127\.0\.0\.1|10\.0\.2\.2))[a-zA-Z0-9]', re.IGNORECASE),
    ),
    (
        "ssl_all_trusting_manager",
        "cleartext_traffic",
        # Custom X509TrustManagers that trust everything bypass certificate pinning.
        re.compile(r'checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustAllCerts|X509TrustManager', re.IGNORECASE),
    ),
    (
        "hostname_verifier_allow_all",
        "cleartext_traffic",
        # ALLOW_ALL_HOSTNAME_VERIFIER disables host validation entirely.
        re.compile(r'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier', re.IGNORECASE),
    ),
    (
        "ssl_error_proceed",
        "cleartext_traffic",
        # onReceivedSslError calling proceed() silently accepts invalid certs.
        re.compile(r'onReceivedSslError[^{]*\{[^}]*\.proceed\s*\(\s*\)', re.IGNORECASE),
    ),
]

# ──────────────────────────────────────────────────────────────────────────────
# Endpoint hunting patterns
# ──────────────────────────────────────────────────────────────────────────────

# URL pattern: captures http(s):// URLs up to the first whitespace/quote/bracket.
# Conservative right-boundary avoids swallowing surrounding code syntax.
_URL_RE: re.Pattern[str] = re.compile(
    r'https?://'                     # scheme (required)
    r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'  # path, query, fragment
    r'(?<![.,;\'\")\]])',            # negative lookbehind: strip trailing punctuation
    re.IGNORECASE,
)

# Strict IPv4 pattern — each octet 0-255, not preceded/followed by digits or dots
# (avoids matching version numbers like "1.2.3.4" inside "version=1.2.3.4.5").
_IPV4_RE: re.Pattern[str] = re.compile(
    r'(?<![.\d])'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)'
    r'(?![.\d])',
)

# Private / loopback ranges to exclude from endpoint results — these are never
# real remote endpoints of interest in a security report.
_PRIVATE_IP_RE: re.Pattern[str] = re.compile(
    r'^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)'
)

# 1. Dummy / placeholder values — discard matches whose lowercased text
#    contains any of these substrings (exact substring match, O(1) per token).
DUMMY_SECRETS: frozenset[str] = frozenset(
    {
        "your_api_key", "your-api-key", "api_key_here",
        "insert_key", "insert-key",
        "example", "sample", "placeholder", "changeme",
        "replace_me", "replace-me", "todo", "fixme",
        "xxxxxxxx", "aaaaaaaa",
        "null", "none", "undefined", "n/a",
        "123456", "12345678", "password", "secret",
        "test123", "abc123", "foobar", "foo", "bar", "baz",
        "enter_your", "add_your", "<key>", "<secret>",
        "0000000000000000",
    }
)

# 2. Contextual noise words — if the LINE containing a match includes any of
#    these tokens, the hit is downgraded to LIKELY_FALSE_POSITIVE rather than
#    discarded entirely (preserves audit trail while flagging low confidence).
NOISY_CONTEXT_WORDS: frozenset[str] = frozenset(
    {
        "test", "mock", "demo", "sample", "fake",
        "dummy", "stub", "fixture", "example",
        "unittest", "androidtest", "espresso",
        "robolectric", "mockito", "testcase",
    }
)

# Pre-compiled word-boundary pattern for context scanning (compiled once,
# reused on every line — far cheaper than re.compile inside the loop).
_NOISY_CONTEXT_RE: re.Pattern[str] = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in NOISY_CONTEXT_WORDS) + r")\b",
    re.IGNORECASE,
)

# 3. Shannon entropy thresholds.
#    Real credentials sit comfortably in 3.0–6.0 bits/char.
#    Values below MIN are likely repetitive placeholders; above MAX are
#    usually binary blobs or random padding, not human-readable secrets.
ENTROPY_MIN: float = 3.0
ENTROPY_MAX: float = 6.0

# Rules that are structural (PEM headers, webhook URLs) — entropy of the
# matched prefix itself is not a useful signal, so we skip the entropy gate
# for these and rely solely on regex + dummy + context filters.
ENTROPY_SKIP_RULES: frozenset[str] = frozenset(
    {
        "private_key_header",
        "slack_webhook",
        "discord_webhook",
        "firebase_url",
        "google_oauth_client_id",
    }
)

# 4. Autogenerated Android files known to produce noisy, meaningless matches.
EXCLUDED_FILENAMES: frozenset[str] = frozenset(
    {
        "R.java", "R2.java",
        "BuildConfig.java", "BuildConfig.kt",
        "Manifest.java",
        "DataBinderMapperImpl.java",
        "BR.java",
        "GeneratedAppGlideModuleImpl.java",
    }
)

# File extensions to scan (skip binaries, images, compiled dex, etc.)
SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".xml", ".java", ".smali", ".kt", ".json",
        ".yaml", ".yml", ".properties", ".gradle",
        ".txt", ".html", ".htm", ".js", ".ts",
        ".config", ".cfg", ".ini", ".env",
    }
)

# Max file size (bytes) to scan — skip huge files that are obviously not secrets
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _redact(value: str, keep: int = 6) -> str:
    """Partially redact a sensitive match for safe logging/output."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "…[REDACTED]"


def _is_scannable(path: Path) -> bool:
    """Return True if the file should be scanned for secrets."""
    if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
        return False
    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            logger.debug("Skipping oversized file: %s", path)
            return False
    except OSError:
        return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Heuristic helpers
# ──────────────────────────────────────────────────────────────────────────────

def calculate_entropy(value: str) -> float:
    """
    Compute the Shannon entropy (bits per character) of *value*.

    Formula: H = -Σ p(c) · log₂(p(c))  for each unique character c.

    Performance notes
    -----------------
    * ``collections.Counter`` is implemented in C — faster than a manual dict
      loop for strings up to a few hundred characters.
    * The entire function is a single O(n) pass with no allocations beyond the
      Counter, making it safe to call thousands of times inside a file scan.

    Returns 0.0 for empty or single-character strings.
    """
    n = len(value)
    if n <= 1:
        return 0.0
    counts = Counter(value)
    # Unrolled slightly: compute p·log2(p) without a separate division each time
    return -sum(
        (freq / n) * math.log2(freq / n)
        for freq in counts.values()
    )


def _is_dummy(raw_match: str) -> bool:
    """
    Return True if *raw_match* is a known placeholder or dummy value.

    Checks whether the lowercased match contains any token from DUMMY_SECRETS
    as a substring.  Substring matching is intentional — catches variants like
    ``YOUR_API_KEY_HERE`` or ``example_secret_value`` without enumerating every
    possible suffix.
    """
    lower = raw_match.lower()
    return any(dummy in lower for dummy in DUMMY_SECRETS)


def _noisy_context_confidence(line: str) -> str:
    """
    Return ``"LIKELY_FALSE_POSITIVE"`` if the source line looks like test/mock
    code, otherwise ``"HIGH"``.

    Using a pre-compiled word-boundary regex is ~10× faster than calling
    ``any(word in line.lower() for word in NOISY_CONTEXT_WORDS)`` because it
    avoids multiple ``str.lower()`` copies and scans the string once.
    """
    return "LIKELY_FALSE_POSITIVE" if _NOISY_CONTEXT_RE.search(line) else "HIGH"


def _passes_entropy_gate(raw_match: str, rule_name: str) -> tuple[bool, float]:
    """
    Run the entropy gate for a regex match.

    Returns
    -------
    (passes: bool, entropy_value: float)

    Rules in ``ENTROPY_SKIP_RULES`` are waved through unconditionally because
    their matched text (e.g., a PEM header line) is structurally valid
    regardless of character distribution.
    """
    if rule_name in ENTROPY_SKIP_RULES:
        # Still compute entropy for the report field — just don't gate on it.
        return True, calculate_entropy(raw_match)

    entropy = calculate_entropy(raw_match)
    passes = ENTROPY_MIN <= entropy <= ENTROPY_MAX
    return passes, entropy


# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Decompilation
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DecompilationResult:
    output_dir: Path
    success: bool
    error_message: str = ""


def decompile_apk(apk_path: Path, output_dir: Path) -> DecompilationResult:
    """
    Run ``apktool d -f <apk_path> -o <output_dir>`` via subprocess.

    Parameters
    ----------
    apk_path   : Absolute path to the APK file.
    output_dir : Directory where apktool should write decompiled output.

    Returns
    -------
    DecompilationResult with success flag and error details on failure.
    """
    logger.info("Starting decompilation: %s → %s", apk_path, output_dir)

    if not apk_path.exists():
        msg = f"APK not found: {apk_path}"
        logger.error(msg)
        return DecompilationResult(output_dir=output_dir, success=False, error_message=msg)

    if shutil.which("apktool") is None:
        msg = "apktool is not installed or not on PATH."
        logger.error(msg)
        return DecompilationResult(output_dir=output_dir, success=False, error_message=msg)

    cmd: list[str] = [
        "apktool", "d",
        "-f",                       # force overwrite
        str(apk_path),
        "-o", str(output_dir),
    ]
    logger.debug("apktool command: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,            # hard ceiling to prevent hangs
        )
    except subprocess.TimeoutExpired:
        msg = "apktool timed out after 120 seconds."
        logger.error(msg)
        return DecompilationResult(output_dir=output_dir, success=False, error_message=msg)
    except FileNotFoundError:
        msg = "apktool binary not found during execution."
        logger.error(msg)
        return DecompilationResult(output_dir=output_dir, success=False, error_message=msg)

    if result.returncode != 0:
        msg = f"apktool exited with code {result.returncode}: {result.stderr.strip()}"
        logger.error(msg)
        return DecompilationResult(output_dir=output_dir, success=False, error_message=msg)

    logger.info("Decompilation successful → %s", output_dir)
    return DecompilationResult(output_dir=output_dir, success=True)


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Manifest parsing
# ──────────────────────────────────────────────────────────────────────────────

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(element: ET.Element, local_name: str) -> str:
    """Retrieve an android-namespaced attribute value, or ''."""
    return element.get(f"{{{ANDROID_NS}}}{local_name}", "")


@dataclass
class ManifestData:
    package_name: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    exported_components: list[ExportedComponent] = field(default_factory=list)
    error: str = ""


def parse_manifest(decompiled_dir: Path) -> ManifestData:
    """
    Parse ``AndroidManifest.xml`` from a decompiled APK directory.

    Extracts:
    - Package name + SDK versions
    - All requested <uses-permission> entries
    - Known dangerous permissions (flagged)
    - All exported activities, services, receivers, and providers
    """
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    data = ManifestData()

    if not manifest_path.exists():
        data.error = f"AndroidManifest.xml not found in {decompiled_dir}"
        logger.error(data.error)
        return data

    logger.info("Parsing manifest: %s", manifest_path)

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        data.error = f"Failed to parse AndroidManifest.xml: {exc}"
        logger.error(data.error)
        return data

    # ── Package metadata ──────────────────────────────────────────────────────
    data.package_name = root.get("package", "unknown")
    logger.info("Package: %s", data.package_name)

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        data.min_sdk = _attr(uses_sdk, "minSdkVersion")
        data.target_sdk = _attr(uses_sdk, "targetSdkVersion")
    logger.info("SDK: min=%s target=%s", data.min_sdk, data.target_sdk)

    # ── Permissions ───────────────────────────────────────────────────────────
    for perm_el in root.findall("uses-permission"):
        perm_name = _attr(perm_el, "name")
        if not perm_name:
            continue
        data.permissions.append(perm_name)
        if perm_name in DANGEROUS_PERMISSIONS:
            data.dangerous_permissions.append(perm_name)
            logger.warning("Dangerous permission found: %s", perm_name)

    logger.info(
        "Permissions: %d total, %d dangerous",
        len(data.permissions),
        len(data.dangerous_permissions),
    )

    # ── Exported components ───────────────────────────────────────────────────
    component_tags = ("activity", "service", "receiver", "provider")
    application_el = root.find("application")

    if application_el is None:
        logger.warning("No <application> element found in manifest.")
        return data

    for comp_type in component_tags:
        for comp_el in application_el.findall(f".//{comp_type}"):
            exported_raw = _attr(comp_el, "exported")
            # 'true' is explicit; also flag components with intent-filters
            # (implicit export prior to API 31)
            intent_filters = comp_el.findall(".//intent-filter")
            is_exported = (
                exported_raw.lower() == "true"
                or (exported_raw == "" and len(intent_filters) > 0)
            )

            if not is_exported:
                continue

            comp_name = _attr(comp_el, "name")
            filter_actions: list[str] = []
            for ifilter in intent_filters:
                for action in ifilter.findall("action"):
                    action_name = _attr(action, "name")
                    if action_name:
                        filter_actions.append(action_name)

            component: ExportedComponent = {
                "name": comp_name,
                "type": comp_type,
                "intent_filters": filter_actions,
            }
            data.exported_components.append(component)
            logger.info("Exported %s: %s", comp_type, comp_name)

    logger.info("Exported components total: %d", len(data.exported_components))
    return data


# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Secret hunting
# ──────────────────────────────────────────────────────────────────────────────

def _scan_file(
    file_path: Path,
    relative_base: Path,
) -> tuple[list[FoundSecret], list[str], list[InsecurePattern]]:
    """
    Single-pass scan of one file for all three finding types simultaneously.

    Returns
    -------
    (secrets, raw_endpoints, insecure_patterns)

    Each line is read exactly once. All three rule sets are evaluated against
    that line in the same loop iteration, so file I/O cost is O(lines) regardless
    of how many rule sets are active.

    Scan order per line
    ───────────────────
    A) SECRET_RULES          → full 4-stage heuristic pipeline (dummy → entropy → context → emit)
    B) INSECURE_CODE_RULES   → regex match only, no entropy gate, always HIGH
    C) URL / IPv4 extraction → regex match, collected raw for dedup in caller
    """
    secrets:          list[FoundSecret]      = []
    raw_endpoints:    list[str]              = []
    insecure:         list[InsecurePattern]  = []
    relative_path = str(file_path.relative_to(relative_base))
    suppressed = 0

    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):

                # ── (A) SECRET RULES — heuristic pipeline ────────────────────
                # context_checked is computed lazily: only once per line if any
                # secret rule fires and survives stages 1 + 2.
                context_checked: str | None = None

                for rule_name, pattern in SECRET_RULES:
                    match = pattern.search(line)
                    if not match:
                        continue

                    raw_match = match.group(1) if match.lastindex else match.group(0)

                    # Stage 1 — dummy / placeholder gate
                    if _is_dummy(raw_match):
                        suppressed += 1
                        logger.debug(
                            "Suppressed [dummy] %s:%d rule=%s match=%r",
                            relative_path, line_no, rule_name, raw_match[:20],
                        )
                        continue

                    # Stage 2 — entropy gate
                    passes, entropy = _passes_entropy_gate(raw_match, rule_name)
                    if not passes:
                        suppressed += 1
                        logger.debug(
                            "Suppressed [entropy=%.2f] %s:%d rule=%s match=%r",
                            entropy, relative_path, line_no, rule_name, raw_match[:20],
                        )
                        continue

                    # Stage 3 — contextual noise (lazy: computed once per line)
                    if context_checked is None:
                        context_checked = _noisy_context_confidence(line)
                    confidence = context_checked

                    if confidence == "LIKELY_FALSE_POSITIVE":
                        logger.debug(
                            "Downgraded [noisy context] %s:%d rule=%s",
                            relative_path, line_no, rule_name,
                        )

                    # Stage 4 — emit
                    preview = _redact(raw_match, keep=8)
                    secrets.append(FoundSecret(
                        file=relative_path,
                        line_number=line_no,
                        rule_name=rule_name,
                        match_preview=preview,
                        entropy=round(entropy, 4),
                        confidence=confidence,
                    ))
                    log_fn = logger.warning if confidence == "HIGH" else logger.info
                    log_fn(
                        "[%s] Secret [%s] in %s:%d entropy=%.2f → %s",
                        confidence, rule_name, relative_path, line_no, entropy, preview,
                    )

                # ── (B) INSECURE CODE RULES — no entropy gate ────────────────
                for rule_name, category, pattern in INSECURE_CODE_RULES:
                    match = pattern.search(line)
                    if not match:
                        continue

                    # Trim to 120 chars max — these are code snippets, readable as-is
                    snippet = match.group(0).strip()[:120]
                    insecure.append(InsecurePattern(
                        file=relative_path,
                        line_number=line_no,
                        rule_name=rule_name,
                        category=category,
                        match_preview=snippet,
                        confidence="HIGH",
                    ))
                    logger.warning(
                        "[INSECURE:%s] %s in %s:%d → %s",
                        category, rule_name, relative_path, line_no, snippet[:60],
                    )

                # ── (C) ENDPOINT EXTRACTION ───────────────────────────────────
                for url_match in _URL_RE.finditer(line):
                    raw_endpoints.append(url_match.group(0))

                for ip_match in _IPV4_RE.finditer(line):
                    ip = ip_match.group(0)
                    # Skip private / loopback — not useful in a security report
                    if not _PRIVATE_IP_RE.match(ip):
                        raw_endpoints.append(ip)

    except (OSError, PermissionError) as exc:
        logger.debug("Could not read %s: %s", file_path, exc)

    if suppressed:
        logger.debug(
            "FP filter suppressed %d secret match(es) in %s", suppressed, relative_path,
        )

    return secrets, raw_endpoints, insecure


def deep_scan(decompiled_dir: Path) -> tuple[
    list[FoundSecret],
    list[str],
    list[InsecurePattern],
]:
    """
    Walk the decompiled APK directory once and collect all three finding types.

    Each eligible file is opened and read exactly once; `_scan_file` fans out
    to all three rule sets in a single line-by-line pass.

    Returns
    -------
    (secrets, endpoints, insecure_patterns)

    ``endpoints`` is globally deduplicated and sorted for deterministic output.
    Private / loopback IPs are excluded before deduplication.
    """
    logger.info("Starting deep scan in: %s", decompiled_dir)

    all_secrets:  list[FoundSecret]     = []
    all_endpoints: set[str]             = set()   # set for O(1) dedup across files
    all_insecure: list[InsecurePattern] = []
    files_scanned  = 0
    files_excluded = 0

    for file_path in decompiled_dir.rglob("*"):
        if not file_path.is_file():
            continue

        # File-level exclusions (autogenerated noise sources)
        if file_path.name in EXCLUDED_FILENAMES:
            files_excluded += 1
            logger.debug("Excluded autogenerated file: %s", file_path.name)
            continue

        if not _is_scannable(file_path):
            continue

        file_secrets, file_endpoints, file_insecure = _scan_file(
            file_path, decompiled_dir
        )
        all_secrets.extend(file_secrets)
        all_endpoints.update(file_endpoints)   # set.update deduplicates immediately
        all_insecure.extend(file_insecure)
        files_scanned += 1

    # Sort for deterministic, diff-friendly output
    sorted_endpoints = sorted(all_endpoints)

    secret_high = sum(1 for s in all_secrets if s["confidence"] == "HIGH")
    secret_fp   = len(all_secrets) - secret_high
    insecure_by_cat: dict[str, int] = {}
    for p in all_insecure:
        insecure_by_cat[p["category"]] = insecure_by_cat.get(p["category"], 0) + 1

    logger.info(
        "Deep scan complete — %d files scanned, %d excluded | "
        "secrets: %d (HIGH=%d, FP=%d) | endpoints: %d | insecure patterns: %d %s",
        files_scanned, files_excluded,
        len(all_secrets), secret_high, secret_fp,
        len(sorted_endpoints),
        len(all_insecure), insecure_by_cat,
    )

    return all_secrets, sorted_endpoints, all_insecure


# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Orchestrator (sync + async wrappers)
# ──────────────────────────────────────────────────────────────────────────────

def run_extraction(apk_path: str | Path) -> ExtractionReport:
    """
    Full synchronous extraction pipeline — Deep Scan edition.

    Stages
    ──────
    1. Decompile via apktool
    2. Parse AndroidManifest.xml  (permissions, exported components)
    3. Deep scan all source files in a single pass per file:
       a. Secret hunt    — heuristic regex + entropy + context filters
       b. Endpoint hunt  — HTTP/HTTPS URLs + public IPv4 addresses
       c. Insecure code  — dangerous API patterns, straight to HIGH confidence
    4. Assemble and return ExtractionReport

    Parameters
    ----------
    apk_path : Path to the APK file to analyse.

    Returns
    -------
    ExtractionReport typed dict — JSON-serialisable, ready for Groq API context.
    """
    apk_path = Path(apk_path).resolve()
    errors: list[str] = []

    logger.info("═══ APK Deep-Scan pipeline START: %s ═══", apk_path.name)

    with tempfile.TemporaryDirectory(prefix="apk_analysis_") as tmpdir:
        output_dir = Path(tmpdir) / "decompiled"

        # ── 1. Decompile ──────────────────────────────────────────────────────
        decompile_result = decompile_apk(apk_path, output_dir)
        if not decompile_result.success:
            errors.append(decompile_result.error_message)
            logger.error("Decompilation failed — returning partial report.")
            return ExtractionReport(
                apk_path=str(apk_path),
                package_name="unknown",
                min_sdk="",
                target_sdk="",
                permissions=[],
                dangerous_permissions=[],
                exported_components=[],
                secrets=[],
                endpoints=[],
                insecure_code_patterns=[],
                errors=errors,
            )

        # ── 2. Parse manifest ─────────────────────────────────────────────────
        manifest_data = parse_manifest(output_dir)
        if manifest_data.error:
            errors.append(manifest_data.error)

        # ── 3. Deep scan (single pass per file) ───────────────────────────────
        secrets, endpoints, insecure_patterns = deep_scan(output_dir)

        # ── 4. Assemble report ────────────────────────────────────────────────
        report = ExtractionReport(
            apk_path=str(apk_path),
            package_name=manifest_data.package_name,
            min_sdk=manifest_data.min_sdk,
            target_sdk=manifest_data.target_sdk,
            permissions=manifest_data.permissions,
            dangerous_permissions=manifest_data.dangerous_permissions,
            exported_components=manifest_data.exported_components,
            secrets=secrets,
            endpoints=endpoints,
            insecure_code_patterns=insecure_patterns,
            errors=errors,
        )

    logger.info(
        "═══ APK Deep-Scan pipeline END | secrets=%d endpoints=%d insecure=%d ═══",
        len(secrets), len(endpoints), len(insecure_patterns),
    )
    return report


async def run_extraction_async(apk_path: str | Path) -> ExtractionReport:
    """
    Async wrapper around run_extraction.

    Runs the blocking pipeline in a thread pool via asyncio.to_thread()
    so it does not block the FastAPI event loop.

    Usage in a FastAPI route
    ------------------------
    .. code-block:: python

        @router.post("/analyze")
        async def analyze_apk(apk: UploadFile) -> ExtractionReport:
            tmp = Path(f"/tmp/{apk.filename}")
            tmp.write_bytes(await apk.read())
            report = await run_extraction_async(tmp)
            return report
    """
    return await asyncio.to_thread(run_extraction, apk_path)


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry-point (quick smoke-test)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python apk_extractor.py <path_to_apk>", file=sys.stderr)
        sys.exit(1)

    report = run_extraction(sys.argv[1])
    print(json.dumps(report, indent=2))
