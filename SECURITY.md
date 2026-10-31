# Security Policy

CyberBag is a security validation framework. Security issues in the framework itself should be handled carefully and responsibly.

## Supported Versions

CyberBag is currently in active research and development. Until formal releases are published, security fixes are expected to target the main development branch.

| Version | Supported |
|---|---|
| main / active development | Yes |
| tagged releases | To be defined |

## Reporting a Vulnerability

If you discover a vulnerability in CyberBag, please do not disclose it publicly before maintainers have had an opportunity to investigate.

Preferred reporting process:

1. Contact the project maintainer privately.
2. Include a concise description of the issue.
3. Provide reproduction steps when safe to do so.
4. Include affected files, endpoints, or components.
5. Describe potential impact.
6. Avoid sharing exploit code beyond what is necessary to validate the issue.

If a private security contact has not yet been published for this repository, open a public issue that requests a private contact channel without including vulnerability details.

## Scope

Security reports may include:

- Authentication or session weaknesses
- Unsafe task execution behavior
- Agent/server trust boundary issues
- Sensitive data exposure
- Insecure default configuration
- Dashboard or API vulnerabilities
- Unsafe handling of telemetry or execution results

Out-of-scope reports include:

- Findings that require unauthorized use of CyberBag itself
- Reports about intentionally executed validation behavior
- Generic dependency reports without demonstrated project impact
- Social engineering or physical attacks

## Operational Safety

CyberBag should only be used in environments where the operator has explicit authorization. The framework is designed for defensive validation and research. It is not intended for unauthorized testing, persistence, evasion, or harmful activity.

## Disclosure Expectations

Maintainers will aim to:

- Acknowledge valid reports promptly when a maintainer contact exists.
- Investigate and reproduce the issue.
- Prioritize fixes based on impact and exploitability.
- Credit reporters when requested and appropriate.

Formal response timelines will be defined when the project publishes its first stable release.
