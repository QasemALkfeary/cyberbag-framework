# CyberBag Roadmap

This roadmap describes intended development direction. It is not a release guarantee. CyberBag should remain grounded in implemented behavior, evidence-backed validation, and safe research practice.

## Near-Term Priorities

| Area | Goal |
|---|---|
| Documentation | Stabilize architecture, setup, detection science, and contribution documentation. |
| Telemetry mapping | Improve expected telemetry definitions for Windows Security, Sysmon, and PowerShell sources. |
| Ability metadata | Add clearer safety notes, cleanup steps, and ATT&CK rationale for abilities. |
| Detection rules | Improve rule explainability and evidence traces. |
| Scoring explanations | Make coverage, fidelity, timeliness, and actionability easier to inspect in the UI. |
| Operator workflow | Smooth scenario execution, evidence review, and report navigation. |

## Medium-Term Priorities

| Area | Goal |
|---|---|
| Evidence normalization | Create more consistent event field handling across telemetry sources. |
| Correlation | Strengthen process tree, user session, host, time-window, and multi-event correlation. |
| Confidence modeling | Improve treatment of sample size, missing data, baseline noise, and uncertainty. |
| Reporting | Add export formats suitable for SOC engineering and academic review. |
| Testing | Add regression tests for scoring, detection logic, and API behavior. |
| Deployment guidance | Document lab, classroom, and controlled enterprise validation deployment patterns. |

## Long-Term Research Directions

| Area | Research Question |
|---|---|
| Detection quality | How can detection results be compared across techniques without hiding weak dimensions? |
| TTD analysis | How stable is Time-to-Detect across telemetry sources and repeated runs? |
| Telemetry drift | Can CyberBag identify when endpoint logging posture changes over time? |
| Dataset generation | Can controlled validation runs produce labeled Windows telemetry datasets? |
| Methodology | How should confidence and uncertainty be reported in purple team validation? |

## Non-Goals

CyberBag does not aim to become:

- A penetration testing framework
- A SIEM replacement
- A malware development framework
- An exploit framework
- A general-purpose endpoint management tool

The project should remain focused on controlled validation and defensive measurement.
