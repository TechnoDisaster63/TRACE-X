"""
TRACE-X shared data models.
Every module normalizes its findings into the Finding schema so the
Evidence Engine and Risk Engine can consume them uniformly.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}


@dataclass
class Finding:
    """A single, evidence-tied observation produced by any analysis module."""
    finding_id: str
    finding: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    evidence: str
    source: str               # e.g. "header:reply_to_vs_from"
    confidence: str           # HIGH | MEDIUM | LOW
    category: str = "GENERAL"

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError(f"Invalid confidence: {self.confidence}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def findings_summary(findings: List[Finding]) -> Dict[str, int]:
    summary = {"total_findings": len(findings), "critical": 0, "high": 0,
               "medium": 0, "low": 0, "info": 0}
    for f in findings:
        summary[f.severity.lower()] += 1
    return summary


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    """Output schema of M01 — EML Parser."""
    from_: Optional[str]
    to: List[str]
    cc: List[str]
    subject: Optional[str]
    date: Optional[str]
    reply_to: Optional[str]
    return_path: Optional[str]
    message_id: Optional[str]
    received: List[str]
    authentication_results: List[str]
    body_plain: str
    body_html_text: str
    urls: List[str]
    attachments: List[Dict[str, Any]]
    raw_headers: Dict[str, Any]
    file_sha256: str
    parse_warnings: List[str] = field(default_factory=list)
    source_filename: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


VALID_OBSERVATION_STATUS = {"OBSERVED", "REPORTED", "DERIVED", "INFERRED"}
VALID_SOURCE_RELIABILITY = {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
VALID_EDGE_TYPES = {"ORIGIN", "DERIVES_FROM", "SUPPORTS", "CORRELATES_WITH", "CONTRADICTS"}


@dataclass(frozen=True)
class SourceLocator:
    """A deterministic pointer to source material without copying raw content."""
    artifact_id: str
    kind: str
    path: str
    occurrence: int = 0
    byte_start: Optional[int] = None
    byte_end: Optional[int] = None


@dataclass(frozen=True)
class EvidenceNode:
    node_id: str
    finding: str
    category: str
    observation_status: str
    source_reliability: str
    analytic_confidence: str
    severity: str
    locators: tuple = ()
    supporting_finding_ids: tuple = ()
    rationale: str = ""

    def __post_init__(self):
        if self.observation_status not in VALID_OBSERVATION_STATUS:
            raise ValueError(f"Invalid observation status: {self.observation_status}")
        if self.source_reliability not in VALID_SOURCE_RELIABILITY:
            raise ValueError(f"Invalid source reliability: {self.source_reliability}")
        if self.analytic_confidence not in VALID_CONFIDENCE:
            raise ValueError(f"Invalid analytic confidence: {self.analytic_confidence}")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")


@dataclass(frozen=True)
class ProvenanceEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    rationale: str = ""

    def __post_init__(self):
        if self.edge_type not in VALID_EDGE_TYPES:
            raise ValueError(f"Invalid edge type: {self.edge_type}")


@dataclass(frozen=True)
class ContradictionRecord:
    contradiction_id: str
    claim_key: str
    node_ids: tuple
    status: str = "UNRESOLVED"
    review_required: bool = True
    rationale: str = "Competing evidence claims are preserved; no claim is silently selected."


@dataclass(frozen=True)
class CaseManifest:
    manifest_version: str
    investigation_id: str
    created_at_utc: str
    input_sha256: str
    artifacts: Dict[str, Dict[str, Any]]
    tool: Dict[str, Any]
    configuration: Dict[str, Any]
    environment: Dict[str, Any]
    graph_hash: str
    warnings: tuple = ()
