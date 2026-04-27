"""OWASP LLM Top 10 (2025) mapping and compliance module.

Provides comprehensive mapping between OWASP LLM Top 10 vulnerability
categories and SentinelGuard scanners, along with compliance checking
and reporting utilities.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional



class OWASPCategory(str, Enum):
    """OWASP LLM Top 10 (2025) vulnerability categories."""

    LLM01 = "LLM01:2025"
    LLM02 = "LLM02:2025"
    LLM03 = "LLM03:2025"
    LLM04 = "LLM04:2025"
    LLM05 = "LLM05:2025"
    LLM06 = "LLM06:2025"
    LLM07 = "LLM07:2025"
    LLM08 = "LLM08:2025"
    LLM09 = "LLM09:2025"
    LLM10 = "LLM10:2025"


@dataclass
class OWASPVulnerability:
    """Describes an OWASP LLM Top 10 vulnerability."""

    id: str
    name: str
    description: str
    risk_level: str
    scanner_names: List[str]
    mitigation_strategies: List[str]
    references: List[str] = field(default_factory=list)


# Full OWASP LLM Top 10 (2025) definitions with scanner mappings
OWASP_LLM_TOP_10: Dict[str, OWASPVulnerability] = {
    "LLM01:2025": OWASPVulnerability(
        id="LLM01:2025",
        name="Prompt Injection",
        description=(
            "An attacker manipulates a large language model through crafted inputs, "
            "causing the LLM to unknowingly execute the attacker's intentions. This "
            "can be done directly by 'jailbreaking' the system prompt or indirectly "
            "through manipulated external inputs, potentially leading to data "
            "exfiltration, social engineering, and other issues."
        ),
        risk_level="CRITICAL",
        scanner_names=["prompt_injection", "invisible_text", "ban_code"],
        mitigation_strategies=[
            "Enforce privilege control on LLM access to backend systems",
            "Add human-in-the-loop for privileged operations",
            "Segregate external content from user prompts",
            "Establish trust boundaries between the LLM and external sources",
            "Monitor LLM input/output for anomalies",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM02:2025": OWASPVulnerability(
        id="LLM02:2025",
        name="Sensitive Information Disclosure",
        description=(
            "LLMs may inadvertently reveal sensitive information such as personal "
            "data, proprietary algorithms, or confidential details in their "
            "responses. This can result in unauthorized data access, privacy "
            "violations, and intellectual property breaches. Consumers of LLM "
            "applications should be aware of how to safely interact with LLMs "
            "and identify the risks associated with unintentionally providing "
            "sensitive data."
        ),
        risk_level="HIGH",
        scanner_names=["data_leakage", "pii", "secrets", "sensitive"],
        mitigation_strategies=[
            "Integrate data sanitization and scrubbing techniques",
            "Implement robust input validation and sanitization methods",
            "Apply principle of least privilege for data access during training",
            "Use PII detection to filter sensitive data from outputs",
            "Establish data governance policies for training data",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM03:2025": OWASPVulnerability(
        id="LLM03:2025",
        name="Supply Chain Vulnerabilities",
        description=(
            "LLM supply chains are susceptible to vulnerabilities that can affect "
            "the integrity of training data, ML models, and deployment platforms. "
            "These vulnerabilities can lead to biased outputs, security breaches, "
            "or system failures. Risks include compromised pre-trained models, "
            "poisoned training data from crowd-sourced data, and insecure plugin "
            "designs that allow malicious inputs."
        ),
        risk_level="HIGH",
        scanner_names=["supply_chain", "ban_code"],
        mitigation_strategies=[
            "Vet data sources and suppliers, including T&Cs and privacy policies",
            "Use only reputable plugins and ensure they have been tested",
            "Apply OWASP SBOM guidelines for component inventory",
            "Use model signing and verified sources for external models",
            "Implement anomaly detection for model supply chain components",
            "Use adversarial robustness testing for models and data pipelines",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM04:2025": OWASPVulnerability(
        id="LLM04:2025",
        name="Data and Model Poisoning",
        description=(
            "Data poisoning occurs when pre-training, fine-tuning, or embedding data "
            "is manipulated to introduce vulnerabilities, backdoors, or biases that "
            "compromise model security, effectiveness, or ethical behavior. Sources "
            "include Common Crawl, WebText, OpenWebText, and similar datasets. "
            "This can lead to degraded performance, biased outputs, downstream "
            "exploitation, and reputation damage."
        ),
        risk_level="HIGH",
        scanner_names=["data_poisoning", "prompt_injection", "toxicity"],
        mitigation_strategies=[
            "Verify supply chain of training data and attestations",
            "Verify legitimacy of data sources during training and fine-tuning",
            "Implement dedicated ML-BOM (Machine Learning Bill of Materials)",
            "Use strict vetting and input filters for training data",
            "Use data poisoning detection techniques (statistical analysis)",
            "Implement adversarial robustness techniques (federated learning, constraints)",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM05:2025": OWASPVulnerability(
        id="LLM05:2025",
        name="Improper Output Handling",
        description=(
            "Improper output handling refers to insufficient validation, sanitization, "
            "and handling of the outputs generated by large language models before "
            "they are passed downstream to other components and systems. Since LLM "
            "output can carry malicious payloads (XSS, SSRF, CSRF, SQL injection, "
            "command injection), this vulnerability can lead to severe consequences "
            "in backend systems."
        ),
        risk_level="CRITICAL",
        scanner_names=["output_sanitization", "malicious_urls", "json"],
        mitigation_strategies=[
            "Treat the model as any other user and validate all outputs",
            "Encode output for downstream consumers to prevent code execution",
            "Implement strict output validation schemas",
            "Apply context-aware sanitization based on downstream usage",
            "Follow OWASP ASVS guidelines for output handling",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM06:2025": OWASPVulnerability(
        id="LLM06:2025",
        name="Excessive Agency",
        description=(
            "An LLM-based system is often granted a degree of agency by its developer "
            "- the ability to call functions or interface with other systems via "
            "extensions (tools, skills, plugins) to undertake actions in response to "
            "a prompt. Excessive agency is the vulnerability that enables damaging "
            "actions in response to unexpected, ambiguous, or manipulated outputs."
        ),
        risk_level="HIGH",
        scanner_names=["excessive_agency", "ban_code"],
        mitigation_strategies=[
            "Limit plugins/tools to minimum necessary functionality",
            "Limit functions available to the minimum required",
            "Avoid open-ended functions where possible",
            "Require human approval for high-impact actions",
            "Implement authorization in downstream systems",
            "Log and monitor all plugin/tool activity",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM07:2025": OWASPVulnerability(
        id="LLM07:2025",
        name="System Prompt Leakage",
        description=(
            "The system prompt leakage vulnerability in LLMs refers to the risk "
            "that the system prompts or instructions used to steer the behavior "
            "of the model can be disclosed through adversarial prompting. These "
            "system prompts may contain sensitive information such as credentials, "
            "operational constraints, internal IPs, or proprietary business logic "
            "that should not be exposed."
        ),
        risk_level="HIGH",
        scanner_names=["system_prompt_leakage", "sensitive", "secrets"],
        mitigation_strategies=[
            "Separate sensitive data from system prompts where possible",
            "Don't rely on system prompts to control LLM behavior securely",
            "Implement output scanning for prompt content leakage",
            "Enforce guardrails to prevent system prompt extraction",
            "Test with adversarial prompt extraction attempts",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM08:2025": OWASPVulnerability(
        id="LLM08:2025",
        name="Vector and Embedding Weaknesses",
        description=(
            "Vectors and embeddings vulnerabilities present security risks in "
            "systems using Retrieval Augmented Generation (RAG) with LLMs. "
            "Weaknesses in how vectors and embeddings are generated, stored, or "
            "retrieved can be exploited to inject harmful content, manipulate "
            "model outputs, or access sensitive information."
        ),
        risk_level="MEDIUM",
        scanner_names=["vector_weakness"],
        mitigation_strategies=[
            "Implement access controls on knowledge base/vector store",
            "Validate and sanitize data before embedding",
            "Regularly audit vector store contents for poisoned entries",
            "Monitor similarity scores for anomalous patterns",
            "Use embedding-level guardrails for topic enforcement",
            "Implement content integrity checks for retrieved documents",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM09:2025": OWASPVulnerability(
        id="LLM09:2025",
        name="Misinformation",
        description=(
            "Misinformation from LLMs poses a core vulnerability for applications "
            "relying on these models. Misinformation occurs when LLMs produce "
            "false or misleading information that appears credible. This can lead "
            "to security breaches, reputational damage, and legal liability. "
            "Hallucination and confabulation are key contributing factors."
        ),
        risk_level="MEDIUM",
        scanner_names=["misinformation", "factual_consistency"],
        mitigation_strategies=[
            "Employ retrieval-augmented generation (RAG) for grounding",
            "Fine-tune models for specific domains to reduce hallucination",
            "Implement cross-reference and verification pipelines",
            "Apply output filtering for unverifiable claims",
            "Use chain-of-thought reasoning to improve factuality",
            "Require citations for factual claims",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    "LLM10:2025": OWASPVulnerability(
        id="LLM10:2025",
        name="Unbounded Consumption",
        description=(
            "Unbounded Consumption refers to the process where an LLM application "
            "allows users to conduct excessive and uncontrolled inferences, leading "
            "to denial-of-service (DoS), economic losses, model theft, and service "
            "degradation. The high computational cost of LLMs makes them particularly "
            "susceptible to resource exhaustion attacks."
        ),
        risk_level="MEDIUM",
        scanner_names=["unbounded_consumption", "token_limit"],
        mitigation_strategies=[
            "Implement input validation to cap prompt size",
            "Cap resource use per request and per user session",
            "Enforce rate limiting on LLM API calls",
            "Monitor resource utilization to detect anomalies",
            "Set strict maximum token limits for input and output",
            "Implement request queuing and backpressure mechanisms",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
}


@dataclass
class ComplianceResult:
    """Result of an OWASP compliance check."""

    category: str
    name: str
    is_covered: bool
    coverage_level: str  # "full", "partial", "none"
    active_scanners: List[str]
    missing_scanners: List[str]
    recommendations: List[str]


@dataclass
class ComplianceReport:
    """Full OWASP LLM Top 10 compliance report."""

    results: List[ComplianceResult]
    overall_coverage: float  # 0.0 - 1.0
    categories_fully_covered: int
    categories_partially_covered: int
    categories_not_covered: int
    recommendations: List[str]

    def summary(self) -> str:
        """Return human-readable summary of the compliance report."""
        lines = [
            "OWASP LLM Top 10 (2025) Compliance Report",
            "=" * 50,
            f"Overall Coverage: {self.overall_coverage:.0%}",
            f"Fully Covered:    {self.categories_fully_covered}/10",
            f"Partially Covered: {self.categories_partially_covered}/10",
            f"Not Covered:      {self.categories_not_covered}/10",
            "",
        ]
        for result in self.results:
            status = {
                "full": "[PASS]",
                "partial": "[WARN]",
                "none": "[FAIL]",
            }.get(result.coverage_level, "[????]")
            lines.append(f"  {status} {result.category}: {result.name}")
            if result.active_scanners:
                lines.append(f"         Scanners: {', '.join(result.active_scanners)}")
            if result.missing_scanners:
                lines.append(f"         Missing:  {', '.join(result.missing_scanners)}")
        if self.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for rec in self.recommendations:
                lines.append(f"  - {rec}")
        return "\n".join(lines)


class OWASPComplianceChecker:
    """Checks SentinelGuard configuration against OWASP LLM Top 10.

    Usage:
        from sentinelguard import SentinelGuard
        from sentinelguard.owasp import OWASPComplianceChecker

        guard = SentinelGuard.strict()
        checker = OWASPComplianceChecker()
        report = checker.check(guard)
        print(report.summary())
    """

    def __init__(self, vulnerabilities: Optional[Dict[str, OWASPVulnerability]] = None):
        self.vulnerabilities = vulnerabilities or OWASP_LLM_TOP_10

    def check(self, guard: Any) -> ComplianceReport:
        """Check a SentinelGuard instance for OWASP LLM Top 10 compliance.

        Args:
            guard: A SentinelGuard instance to check.

        Returns:
            ComplianceReport with detailed coverage analysis.
        """
        active_prompt = set(guard.prompt_scanner_names)
        active_output = set(guard.output_scanner_names)
        all_active = active_prompt | active_output

        results = []
        fully_covered = 0
        partially_covered = 0
        not_covered = 0
        all_recommendations = []

        for vuln_id, vuln in self.vulnerabilities.items():
            required = set(vuln.scanner_names)
            active = required & all_active
            missing = required - all_active

            if len(active) == len(required):
                coverage_level = "full"
                fully_covered += 1
            elif len(active) > 0:
                coverage_level = "partial"
                partially_covered += 1
            else:
                coverage_level = "none"
                not_covered += 1

            recommendations = []
            if missing:
                recommendations.append(
                    f"Enable scanners: {', '.join(sorted(missing))} for {vuln.name}"
                )
            if coverage_level == "none":
                recommendations.extend(vuln.mitigation_strategies[:2])
                all_recommendations.append(
                    f"[{vuln.id}] {vuln.name}: No scanners active. "
                    f"Enable: {', '.join(sorted(required))}"
                )

            results.append(ComplianceResult(
                category=vuln.id,
                name=vuln.name,
                is_covered=coverage_level != "none",
                coverage_level=coverage_level,
                active_scanners=sorted(active),
                missing_scanners=sorted(missing),
                recommendations=recommendations,
            ))

        total = len(self.vulnerabilities)
        coverage = (fully_covered + partially_covered * 0.5) / total if total > 0 else 0.0

        return ComplianceReport(
            results=results,
            overall_coverage=coverage,
            categories_fully_covered=fully_covered,
            categories_partially_covered=partially_covered,
            categories_not_covered=not_covered,
            recommendations=all_recommendations,
        )

    def get_vulnerability(self, category: str) -> Optional[OWASPVulnerability]:
        """Get vulnerability details by category ID."""
        return self.vulnerabilities.get(category)

    def get_recommended_scanners(self, category: str) -> List[str]:
        """Get recommended scanner names for a vulnerability category."""
        vuln = self.vulnerabilities.get(category)
        return vuln.scanner_names if vuln else []

    def get_all_required_scanners(self) -> Dict[str, List[str]]:
        """Get all required scanners grouped by OWASP category."""
        return {
            vuln_id: vuln.scanner_names
            for vuln_id, vuln in self.vulnerabilities.items()
        }
