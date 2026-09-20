"""
TRACE-X core configuration.
Central place for limits, thresholds, and trusted-domain context.
"""
import os

# ---- File / parsing safety limits ----
MAX_EML_SIZE_BYTES = 25 * 1024 * 1024       # 25 MB hard cap on input .eml
MAX_ATTACHMENT_SIZE_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS_PER_EMAIL = 50
MAX_URLS_PER_EMAIL = 500
MAX_RECEIVED_HOPS = 50

# ---- Output paths ----
OUTPUT_DIR = os.environ.get("TRACE_X_OUTPUT_DIR", "output")
REPORTS_DIR = os.environ.get("TRACE_X_REPORTS_DIR", "reports")

# ---- Trusted domain context (explicitly supplied, never assumed) ----
# Populate at call time via analyze_email(..., trusted_domains=[...])
DEFAULT_TRUSTED_DOMAINS = []

# ---- URL shortener indicators (static list, informational signal only) ----
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
}

SUSPICIOUS_URL_KEYWORDS = {
    "verify", "login", "secure", "account", "update", "confirm",
    "banking", "invoice", "payment", "reset", "unlock", "suspend",
    "urgent", "click", "wallet",
}

# ---- Severity ordering (for sorting / risk aggregation) ----
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ---- Risk engine thresholds (documented, not arbitrary-hidden) ----
RISK_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH": 55,
    "MEDIUM": 30,
    "LOW": 0,
}
