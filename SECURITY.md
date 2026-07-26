# Security Policy

SentinelGuard is a security-focused project. Please report vulnerabilities
responsibly and avoid posting exploit details, raw prompts, credentials, or
sensitive data in public issues.

## Supported Versions

Security fixes are prioritized for:

| Version | Support |
| --- | --- |
| Latest PyPI release | Supported |
| `main` branch | Supported for upcoming fixes |
| Older releases | Best effort |

## Reporting A Vulnerability

Use GitHub private vulnerability reporting if it is enabled for the repository.
If private reporting is not available, open a public GitHub issue with only a
brief high-level description and ask for a private disclosure channel. Do not
include exploit details, real secrets, logs containing PII, or private customer
data in a public issue.

Please include, when safe:

- affected version or commit
- affected component, such as scanner, gateway auth, provider routing, cache,
  audit logging, or CLI
- impact and expected security boundary
- minimal synthetic reproduction steps
- whether the issue is already public

## Scope

Examples of in-scope issues:

- authentication or authorization bypass in gateway mode
- prompt, response, secret, or PII leakage caused by SentinelGuard behavior
- unsafe logging of raw prompts, outputs, PII, or secrets
- bypasses of documented policy decisions
- dependency or packaging vulnerabilities that affect SentinelGuard users
- denial-of-service issues in parser, scanner, or gateway paths

Examples that are usually out of scope:

- model hallucination without a SentinelGuard security boundary failure
- upstream provider outage or provider-side vulnerability
- vulnerabilities in user applications that do not depend on SentinelGuard
- reports using real third-party secrets or personal data

## Disclosure Expectations

Please give maintainers reasonable time to investigate and release a fix before
public disclosure. We will try to acknowledge reports quickly, clarify impact,
and coordinate remediation steps when a report is valid.
