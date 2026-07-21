# Submission Requirements Register

Last reviewed: 2026-07-21

This register separates organizer statements from SolGuard planning assumptions. An
unanswered question remains `UNCONFIRMED`; internal plans and event-page marketing copy
do not convert it into a rule.

## Sources

1. Organizer event listing and organizer messages supplied by the project owner,
   captured on 2026-07-21.
2. `SolGuard_Documentation.pdf`, reviewed on 2026-07-21. This is an internal project
   planning document, not an organizer response or authoritative competition rule.

No organizer rulebook, checkpoint specification, submission form, or direct organizer
answer has been supplied yet.

## Confirmed from the supplied organizer material

| Topic | Confirmed statement | Source | Implementation consequence |
|---|---|---|---|
| Format | The event includes technical and physical challenges. | Organizer message dated 2026-07-16 | Keep the technical demo independently operable and portable. |
| Checkpoints | Participants race across checkpoints; the slowest participant may be eliminated at each checkpoint. | Event listing captured 2026-07-21 | Optimize for a fast, reliable demonstration and retain the offline fallback. |
| Domain | Challenges focus on agentic finance and mention existing payment rails, Solana, x402, Pay.sh, and CoralOS. | Event listing captured 2026-07-21 | Treat these as relevant technologies, not mandatory integrations unless an organizer confirms that requirement. |
| Broadcast | The event is intended to be livestreamed. | Event listing captured 2026-07-21 | Avoid secrets and personal information in all visible output. |
| Duration | An organizer message says the event runs for approximately ten hours. The public listing displays 10:00 on 25 July to 00:00 on 26 July. | Organizer message dated 2026-07-16 and listing captured 2026-07-21 | The two timings are not equivalent; request the exact build and submission window. |

## Organizer confirmation still required

| Requirement question | Status | Current safe assumption | Required answer/evidence |
|---|---|---|---|
| Is pre-event code permitted? | `UNCONFIRMED` | Treat the existing repository as rehearsal and be prepared to rebuild the required portion during the live window. | Written organizer response stating what may be prepared beforehand and what must be created live. |
| Which sponsor technologies are mandatory? | `UNCONFIRMED` | Do not assume that mentioning Solana, x402, Pay.sh, or CoralOS makes each one mandatory. | Checkpoint or judging rules identifying required protocols and minimum integration depth. |
| What are the judging dimensions? | `UNCONFIRMED` | Prioritize a working security proof, speed, clarity, and truthful evidence without assigning invented weights. | Published rubric or written organizer response. |
| What exactly causes checkpoint elimination? | `PARTIAL` | The supplied listing says the slowest participant is eliminated, but does not define timing start/end, tie-breaking, or correctness gates. | Checkpoint instructions covering timing and acceptance criteria. |
| What repository and licensing evidence is required? | `UNCONFIRMED` | Keep the public MIT-licensed repository, signed commits, CI, and reproducible run instructions ready. | Submission checklist or written organizer response. |
| What team evidence is required? | `UNCONFIRMED` | Maintain accurate authorship and contributor history; do not infer team-size rules. | Eligibility and team-registration rules. |
| Are sandbox transactions acceptable? | `UNCONFIRMED` | Use Pay.sh sandbox, Solana devnet identifiers, and clearly labelled simulation; do not use production funds. | Written confirmation of accepted network and settlement evidence. |
| What presentation time and equipment are available? | `UNCONFIRMED` | Maintain the two-minute live flow and 75-second offline recording as internal fallbacks. | Stage duration, connectivity, display, audio, QR, and device rules. |
| What files or links must be submitted? | `UNCONFIRMED` | Keep repository, architecture, run instructions, evidence manifest, recording, and screenshots ready. | Submission form or checklist with deadlines and required formats. |

## Scope mapping

| Possible requirement | Existing SolGuard evidence | Change only if confirmed |
|---|---|---|
| Working payment path | Pay.sh sandbox adapter and deterministic simulated settlement | Add another mandatory sponsor adapter only when required. |
| Solana-compatible x402 flow | x402 v2 adapter targets official Solana devnet identifiers and remains simulated until a safe funded test is explicitly required. | Add real devnet signing/settlement only with approved wallet handling and time budget. |
| Security demonstration | Mandate policy, behavioural controls, replay protection, pre-signing authorization, audit receipts, and blocked-wallet proof | Preserve the four documented detection rules. |
| Offline presentation | 75-second recording, static runtime evidence states, QR code, and machine-readable manifest | Re-record only if the demonstrated build changes. |
| Public repository | MIT license, protected branches, required CI, signed source and evidence commits | Adjust visibility or submission structure only on written instruction. |

## Questions to send to organizers

1. May participants use code written before the live event? If yes, what must be built or
   changed during the event window?
2. Which technologies are mandatory at each checkpoint, and what constitutes a valid
   integration?
3. Are sandbox, testnet, devnet, and simulated settlements accepted, and how must each
   be labelled?
4. What are the judging criteria, checkpoint timing rules, correctness gates, and
   elimination tie-breakers?
5. What repository, license, commit-history, team, and submission artifacts are
   required?
6. How long is the final presentation, and what network, display, audio, and device
   facilities will be available?

Issue #17 must remain open until answers are recorded with the responding organizer,
source, and date.
