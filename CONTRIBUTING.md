# Contributing to CyberBag

Thank you for your interest in CyberBag. This project sits at the intersection of adversary emulation, Windows telemetry, detection engineering, and defensive measurement. Contributions should improve the framework's ability to validate detection quality safely, reproducibly, and transparently.

## Contribution Principles

CyberBag is maintained around the following expectations:

- Preserve the distinction between validation tooling and offensive tooling.
- Do not introduce behavior whose primary purpose is unauthorized access, stealth, persistence, or harm.
- Keep detection claims tied to telemetry evidence.
- Prefer explicit methodology over opaque scoring or unexplained automation.
- Document assumptions, prerequisites, and safety implications.
- Avoid overstating functionality that is not implemented.

## High-Value Contribution Areas

| Area | Examples |
|---|---|
| Windows telemetry | Event source mapping, Sysmon configuration notes, PowerShell logging behavior, Security Log audit policy guidance. |
| ATT&CK ability metadata | Technique mapping, expected telemetry, cleanup notes, safety classification. |
| Detection validation | Rule predicates, evidence matching, test cases, correlation behavior. |
| Scoring | Coverage, fidelity, timeliness, actionability, AHP review, confidence modeling. |
| Documentation | Setup guides, architecture notes, diagrams, operator workflows, research context. |
| Dashboard | Evidence views, score explanations, scenario timelines, usability improvements. |

## Development Workflow

1. Open an issue for substantial design changes.
2. Keep pull requests focused and reviewable.
3. Avoid unrelated formatting churn.
4. Include documentation updates when behavior or assumptions change.
5. Add tests or validation notes when practical.
6. Describe manual verification steps in the pull request.

## Safety Review for Abilities

Any contribution that executes endpoint behavior should include:

- ATT&CK technique ID and tactic
- Clear description of the behavior
- Required privileges
- Expected telemetry sources and event IDs where known
- Cleanup steps
- Operational risk notes
- Rationale for why the behavior is safe for controlled validation

Maintainers may reject ability contributions that are too destructive, too stealth-oriented, poorly documented, or outside CyberBag's validation purpose.

## Documentation Standards

Documentation should be:

- Technically precise
- Clear about implemented versus planned behavior
- Evidence-oriented
- Friendly to SOC engineers and researchers
- Free of fake metrics, fake screenshots, or unverifiable claims

Use Mermaid diagrams where they clarify architecture or workflows. Store reusable diagram source in `docs/diagrams/`.

## Pull Request Checklist

Before requesting review, confirm:

- The change does not break existing `agent/` or `server/` structure unnecessarily.
- New behavior is documented.
- Security and safety implications are described.
- Commands or setup steps were manually checked where possible.
- Markdown links resolve.
- Placeholder content is clearly marked as placeholder.

## Code Style

CyberBag currently favors straightforward Python, explicit data flow, and inspectable logic over heavy abstraction. Match local style and keep changes easy to audit.

## Responsible Research

CyberBag exists to improve defensive validation. Contributions that shift the project toward exploitation, unauthorized access, or covert operation are out of scope.
