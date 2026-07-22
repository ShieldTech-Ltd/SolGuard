"use strict";

const elements = {
  actionStatus: document.getElementById("action-status"),
  agentState: document.getElementById("agent-state"),
  allowCount: document.getElementById("allow-count"),
  approvalCount: document.getElementById("approval-count"),
  auditChainState: document.getElementById("audit-chain-state"),
  auditContent: document.getElementById("audit-content"),
  auditDialog: document.getElementById("audit-dialog"),
  auditRetained: document.getElementById("audit-retained"),
  blockCount: document.getElementById("block-count"),
  blockedContext: document.getElementById("blocked-context"),
  decisionAmount: document.getElementById("decision-amount"),
  decisionCopy: document.getElementById("decision-copy"),
  decisionLatency: document.getElementById("decision-latency"),
  decisionRequest: document.getElementById("decision-request"),
  decisionValue: document.getElementById("decision-value"),
  eventList: document.getElementById("event-list"),
  guideAuto: document.getElementById("guide-auto"),
  guideBack: document.getElementById("guide-back"),
  guideCopy: document.getElementById("guide-copy"),
  guideEvidenceSource: document.getElementById("guide-evidence-source"),
  guideFactsList: document.getElementById("guide-facts-list"),
  guidedDemo: document.getElementById("guided-demo"),
  guideKicker: document.getElementById("guide-kicker"),
  guideNext: document.getElementById("guide-next"),
  guidePrimaryEvidence: document.querySelector(".guide-primary-evidence"),
  guideProgressLabel: document.getElementById("guide-progress-label"),
  guideProgressTrack: document.getElementById("guide-progress-track"),
  guideResultDetail: document.getElementById("guide-result-detail"),
  guideResultLabel: document.getElementById("guide-result-label"),
  guideResultValue: document.getElementById("guide-result-value"),
  guideStepCount: document.getElementById("guide-step-count"),
  guideTitle: document.getElementById("guide-title"),
  lastSettlement: document.getElementById("last-settlement"),
  mandateBlocked: document.getElementById("mandate-blocked"),
  mandateHeading: document.getElementById("mandate-heading"),
  mandateLimit: document.getElementById("mandate-limit"),
  mandateMode: document.getElementById("mandate-mode"),
  mandatePurpose: document.getElementById("mandate-purpose"),
  mandateValidUntil: document.getElementById("mandate-valid-until"),
  privacyDetail: document.getElementById("privacy-detail"),
  privacyState: document.getElementById("privacy-state"),
  protectedValue: document.getElementById("protected-value"),
  reasonList: document.getElementById("reason-list"),
  receiptDetail: document.getElementById("receipt-detail"),
  receiptState: document.getElementById("receipt-state"),
  scenarioName: document.getElementById("scenario-name"),
  settlementDetail: document.getElementById("settlement-detail"),
  settlementState: document.getElementById("settlement-state"),
  settlementType: document.getElementById("settlement-type"),
  signerDetail: document.getElementById("signer-detail"),
  signerState: document.getElementById("signer-state"),
  systemStatus: document.getElementById("system-status"),
  walletBalance: document.getElementById("wallet-balance"),
};

const buttons = Array.from(document.querySelectorAll("button[data-action]"));
const scenarioButtons = Array.from(document.querySelectorAll("button[data-scenario]"));
const guideScenarioButtons = Array.from(document.querySelectorAll("button[data-guide-action]"));
const guideNodes = Array.from(document.querySelectorAll("[data-guide-node]"));
const pipelineSteps = Object.fromEntries(
  Array.from(document.querySelectorAll("[data-pipeline]")).map((element) => [
    element.dataset.pipeline,
    element,
  ]),
);
const guardChecks = {
  integrity: document.getElementById("integrity-check"),
  mandate: document.getElementById("mandate-check"),
  behaviour: document.getElementById("behaviour-check"),
  authorization: document.getElementById("authorization-check"),
};

const scenarioLabels = {
  COMPOUND_DRAIN: "Compound drain",
  NEW_RECIPIENT: "First-seen recipient",
  NORMAL_PAYMENT: "Normal payment",
  READY: "Ready",
  REPLAY_ATTACK: "Replay attack",
};

const reasonLabels = {
  DETECTION_AMOUNT_ANOMALY: "AMOUNT AT LEAST 8X BASELINE",
  DETECTION_COMPOUND_DRAIN: "COMPOUND DRAIN PATTERN",
  DETECTION_RECIPIENT_NOVEL: "FIRST-SEEN RECIPIENT",
  DETECTION_VELOCITY: "HIGH PAYMENT VELOCITY",
  POLICY_AMOUNT_LIMIT: "MANDATE LIMIT EXCEEDED",
  POLICY_RECIPIENT_BLOCKED: "RECIPIENT HARD-BLOCKED",
  POLICY_RECIPIENT_NOT_ALLOWED: "RECIPIENT NOT ALLOWED",
  REQUEST_EXPIRED: "REQUEST EXPIRED",
  REQUEST_INVALID: "REQUEST INVALID",
  REQUEST_REPLAYED: "NONCE REPLAY DETECTED",
  SYSTEM_FAILURE: "SECURITY DEPENDENCY FAILED",
};

let isBusy = false;
let guideAction = "attack";
let guideStep = 0;
let guideState = null;
let guideAudit = null;
let guideAutoRunning = false;
let guideError = "";

const guideScenarioLabels = {
  approval: "unknown recipient",
  attack: "compound drain",
  normal: "safe API payment",
  replay: "replay attack",
};

const guideNodeNames = [
  "agent",
  "normalize",
  "integrity",
  "mandate",
  "behaviour",
  "authorization",
  "wallet",
  "evidence",
];

function textElement(tag, value, className = "") {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function decisionClass(decision) {
  if (decision === "ALLOW") return "allow";
  if (decision === "REQUIRE_APPROVAL") return "approval";
  return "block";
}

function decisionLabel(decision) {
  return decision === "REQUIRE_APPROVAL" ? "APPROVAL REQUIRED" : decision;
}

function humanReason(reason) {
  return reasonLabels[reason] || reason.replaceAll("_", " ");
}

function shortDigest(value, visible = 18) {
  if (!value) return "None";
  return value.length > visible ? `${value.slice(0, visible)}...` : value;
}

function formatObservedAt(value, includeZone = false) {
  const observed = new Date(value);
  if (Number.isNaN(observed.getTime())) return value;
  const formatted = observed.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
  });
  return includeZone ? `${formatted} UTC` : formatted;
}

function formatDate(value) {
  if (!value) return "Runtime scoped";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-GB", {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
    timeZone: "UTC",
    year: "numeric",
  });
}

function redactionEvidence(event) {
  const counts = event.sanitized_metadata.redaction_counts;
  const entries = Object.entries(counts).filter(([, count]) => count > 0);
  return {
    categories: entries.map(([category]) => category.replaceAll("_", " ")),
    total: entries.reduce((sum, [, count]) => sum + count, 0),
  };
}

function guideFacts(entries) {
  elements.guideFactsList.replaceChildren();
  for (const [term, description] of entries) {
    const row = document.createElement("div");
    row.append(textElement("dt", term), textElement("dd", String(description)));
    elements.guideFactsList.append(row);
  }
}

function setGuideEvidence({ label, value, detail, tone = "", facts, source }) {
  elements.guideResultLabel.textContent = label;
  elements.guideResultValue.textContent = value;
  elements.guideResultDetail.textContent = detail;
  elements.guidePrimaryEvidence.className = `guide-primary-evidence ${tone}`.trim();
  elements.guideEvidenceSource.textContent = source;
  guideFacts(facts);
}

function guideStageStatus(event, index) {
  if (!event) return { className: "", detail: "Waiting" };
  const reasons = new Set(event.reason_codes);
  const integrityBlocked = isIntegrityBlock(reasons);
  const policyReasons = event.reason_codes.filter((reason) => reason.startsWith("POLICY_"));
  const detectionReasons = event.reason_codes.filter((reason) => reason.startsWith("DETECTION_"));
  if (index === 0) return { className: "complete", detail: "Submitted" };
  if (index === 1) return { className: "complete", detail: "Normalized" };
  if (index === 2) {
    return integrityBlocked
      ? { className: "block", detail: humanReason(event.reason_codes[0]) }
      : { className: "complete", detail: "Fresh request" };
  }
  if (index === 3) {
    if (integrityBlocked) return { className: "skipped", detail: "Not evaluated" };
    return policyReasons.length
      ? { className: "block", detail: humanReason(policyReasons[0]) }
      : { className: "complete", detail: "Authorized" };
  }
  if (index === 4) {
    if (integrityBlocked || policyReasons.length) return { className: "skipped", detail: "Not evaluated" };
    if (!detectionReasons.length) return { className: "complete", detail: "Clean" };
    return event.decision === "REQUIRE_APPROVAL"
      ? { className: "warn", detail: "Flagged" }
      : { className: "block", detail: "Block signal" };
  }
  if (index === 5) {
    if (event.decision === "ALLOW") return { className: "complete", detail: "Issued" };
    if (event.decision === "REQUIRE_APPROVAL") return { className: "warn", detail: "Paused" };
    return { className: "block", detail: "Withheld" };
  }
  if (index === 6) {
    return event.signing_state === "NOT_SIGNED"
      ? { className: "block", detail: "Not called" }
      : { className: "complete", detail: "Signed - simulated" };
  }
  return { className: "complete", detail: "Hash-linked" };
}

function renderGuideFlow(event) {
  guideNodes.forEach((node, index) => {
    const status = guideStageStatus(event, index);
    const reached = guideStep > index;
    node.className = reached ? status.className : "";
    if (guideStep === index + 1) node.classList.add("active");
    node.querySelector("small").textContent = reached ? status.detail : "Waiting";
  });
}

function renderGuideProgress() {
  if (!elements.guideProgressTrack.childElementCount) {
    for (let index = 1; index <= guideNodeNames.length; index += 1) {
      const button = document.createElement("button");
      button.type = "button";
      button.setAttribute("aria-label", `Open walkthrough step ${index}`);
      button.addEventListener("click", () => {
        if (!guideState) return;
        guideStep = index;
        renderGuide();
      });
      elements.guideProgressTrack.append(button);
    }
  }
  Array.from(elements.guideProgressTrack.children).forEach((button, index) => {
    button.disabled = !guideState;
    button.className = index + 1 < guideStep ? "complete" : index + 1 === guideStep ? "active" : "";
  });
}

function guideStageContent(event, mandate) {
  const reasons = new Set(event.reason_codes);
  const policyReasons = event.reason_codes.filter((reason) => reason.startsWith("POLICY_"));
  const detectionReasons = event.reason_codes.filter((reason) => reason.startsWith("DETECTION_"));
  const redactions = redactionEvidence(event);
  const source = `Returned by /api/demo/${guideAction}`;

  if (guideStep === 1) {
    return {
      kicker: "STEP 1 · AGENT INTENT",
      title: "The autonomous agent requests a payment",
      copy: "This is the real request outcome returned by the selected local scenario—not a pre-filled dashboard counter.",
      evidence: {
        label: "PAYMENT INTENT",
        value: `${event.amount} ${event.asset} to ${event.recipient}`,
        detail: "The agent submits intent. SolGuard still controls whether a signing authorization can exist.",
        facts: [["Request ID", event.request_id], ["Agent", event.agent_id], ["Observed", formatObservedAt(event.observed_at, true)]],
        source,
      },
    };
  }
  if (guideStep === 2) {
    return {
      kicker: "STEP 2 · CANONICAL REQUEST",
      title: "One immutable request crosses the security boundary",
      copy: "SolGuard binds the amount, recipient, mandate, metadata and request identity into the canonical digest used by later controls.",
      evidence: {
        label: "NORMALIZED",
        value: "Canonical payment request created",
        detail: "Downstream checks and the audit receipt refer to this exact request digest.",
        facts: [["Request digest", shortDigest(event.request_digest, 34)], ["Asset", event.asset], ["Delegated purpose", mandate.purpose]],
        source,
      },
    };
  }
  if (guideStep === 3) {
    const blocked = isIntegrityBlock(reasons);
    return {
      kicker: "STEP 3 · INTEGRITY",
      title: blocked ? "A duplicate request dies before policy evaluation" : "Freshness and replay checks pass",
      copy: blocked ? "The nonce has already been consumed. SolGuard fails closed before mandate, behaviour, authorization or wallet signing." : "The request is current, structurally valid and has not reused a consumed nonce.",
      evidence: {
        label: blocked ? "BLOCK" : "PASS",
        value: blocked ? humanReason(event.reason_codes[0]) : "Fresh request accepted",
        detail: blocked ? "No later control or signer needs to trust this request." : "The request can continue to the financial mandate.",
        tone: blocked ? "block" : "allow",
        facts: [["Integrity result", blocked ? humanReason(event.reason_codes[0]) : "Valid + fresh"], ["Request ID", event.request_id], ["Next boundary", blocked ? "Stopped" : "Financial mandate"]],
        source,
      },
    };
  }
  if (guideStep === 4) {
    const skipped = isIntegrityBlock(reasons);
    const blocked = policyReasons.length > 0;
    return {
      kicker: "STEP 4 · FINANCIAL MANDATE",
      title: skipped ? "Policy is not evaluated after an integrity block" : blocked ? "The agent exceeds its delegated authority" : "The payment fits the agent's mandate",
      copy: skipped ? "Fail-closed ordering prevents rejected traffic from reaching later controls." : "The mandate is configured by a human once; SolGuard enforces it automatically for every payment.",
      evidence: {
        label: skipped ? "NOT EVALUATED" : blocked ? "BLOCK" : "PASS",
        value: skipped ? "Stopped at integrity" : blocked ? humanReason(policyReasons[0]) : `${event.amount} ${event.asset} is within the ${mandate.max_single_payment} ${event.asset} limit`,
        detail: skipped ? "The invalid request cannot influence policy or behavioural state." : "Recipient, amount, asset, purpose and validity are checked before authorization.",
        tone: blocked ? "block" : skipped ? "" : "allow",
        facts: [["Maximum payment", `${mandate.max_single_payment} ${event.asset}`], ["Recipient policy", mandate.policy_mode.replaceAll("_", " ")], ["Hard-block list", mandate.blocked_recipients.join(", ") || "None"]],
        source,
      },
    };
  }
  if (guideStep === 5) {
    const skipped = isIntegrityBlock(reasons) || policyReasons.length > 0;
    const warned = event.decision === "REQUIRE_APPROVAL";
    const blocked = detectionReasons.length > 0 && event.decision === "BLOCK";
    const labels = detectionReasons.map(humanReason);
    return {
      kicker: "STEP 5 · BEHAVIOURAL ANALYSIS",
      title: skipped ? "Rejected traffic cannot poison the behavioural baseline" : warned ? "Anomaly detected: pause for exceptional review" : blocked ? "Multiple weak signals combine into a hard block" : "Behaviour matches the clean baseline",
      copy: skipped ? "SolGuard records the security outcome without learning from traffic that failed an earlier boundary." : "Velocity alone flags; the documented compound condition is required to block this drain scenario.",
      evidence: {
        label: skipped ? "NOT EVALUATED" : warned ? "FLAG" : blocked ? "BLOCK" : "PASS",
        value: skipped ? "Stopped before detection" : labels.length ? labels.join(" + ") : "No behavioural rule fired",
        detail: blocked ? "New recipient, elevated amount and high velocity are present together." : warned ? "No automatic signing authorization is issued." : "The clean request can proceed.",
        tone: warned ? "warn" : blocked ? "block" : skipped ? "" : "allow",
        facts: [["Triggered rules", labels.join(" · ") || "None"], ["Decision so far", decisionLabel(event.decision)], ["Baseline protection", skipped ? "Not updated" : "Only allowed traffic learns"]],
        source,
      },
    };
  }
  if (guideStep === 6) {
    const allowed = event.decision === "ALLOW";
    const warned = event.decision === "REQUIRE_APPROVAL";
    return {
      kicker: "STEP 6 · AUTHORIZATION",
      title: allowed ? "SolGuard issues one request-bound authorization" : warned ? "SolGuard pauses without authorizing the wallet" : "SolGuard withholds authorization",
      copy: allowed ? "The authorization is short-lived, bound to this exact request and consumed once at the wallet boundary." : "A decision is useful only if the wallet boundary enforces it. Without authorization, signing cannot begin.",
      evidence: {
        label: decisionLabel(event.decision),
        value: allowed ? "Single-use authorization issued" : warned ? "Exceptional review required" : "No authorization exists",
        detail: `${event.latency_ms} ms measured by the running gateway for this decision.`,
        tone: allowed ? "allow" : warned ? "warn" : "block",
        facts: [["Final decision", decisionLabel(event.decision)], ["Reason codes", event.reason_codes.map(humanReason).join(" · ") || "All controls passed"], ["Gateway latency", `${event.latency_ms} ms`]],
        source,
      },
    };
  }
  if (guideStep === 7) {
    const signed = event.signing_state !== "NOT_SIGNED";
    return {
      kicker: "STEP 7 · WALLET BOUNDARY",
      title: signed ? "The allowed request reaches simulated signing" : "The wallet signer is never called",
      copy: signed ? "This local path consumes the authorization and produces clearly labelled simulated settlement evidence." : "Stopping the signature is the security outcome: the blocked request cannot move funds.",
      evidence: {
        label: signed ? "SIGNED · SIMULATED" : "NOT CALLED",
        value: signed ? `${event.amount} ${event.asset} settled in simulation` : `${event.amount} ${event.asset} prevented from signing`,
        detail: signed ? "No real funds moved. A verified devnet signature would be shown separately." : "The wallet balance is unchanged by this blocked request.",
        tone: signed ? "allow" : "block",
        facts: [["Signing state", event.signing_state.replaceAll("_", " ")], ["Settlement reference", event.settlement_reference ? shortDigest(event.settlement_reference, 34) : "None"], ["Current wallet balance", `${guideState.wallet_balance} ${event.asset}`]],
        source,
      },
    };
  }
  const chainValid = guideAudit?.valid_chain === true;
  return {
    kicker: "STEP 8 · VERIFIABLE EVIDENCE",
    title: "The decision becomes a portable, hash-linked receipt",
    copy: "The dashboard shows sanitized metadata and a receipt digest produced from the running event. Reviewers can open the complete local chain.",
    evidence: {
      label: chainValid ? "VALID HASH-LINKED CHAIN" : "EVIDENCE AVAILABLE",
      value: decisionLabel(event.decision) + " is recorded without exposing supported PII patterns",
      detail: redactions.total ? `${redactions.total} sensitive value${redactions.total === 1 ? "" : "s"} redacted before display.` : "No supported sensitive pattern was present in this request.",
      tone: chainValid ? "allow" : "",
      facts: [["Receipt digest", shortDigest(event.receipt_digest, 34)], ["Policy digest", shortDigest(event.policy_version, 34)], ["Retained receipts", guideAudit?.retained ?? "Unavailable"]],
      source: "Returned by /api/audit",
    },
  };
}

function renderGuide() {
  renderGuideProgress();
  elements.guideBack.disabled = guideStep === 0 || guideAutoRunning;
  elements.guideAuto.textContent = guideAutoRunning ? "Stop auto-play" : "Auto-play";
  guideScenarioButtons.forEach((button) => { button.disabled = guideAutoRunning; });

  if (!guideState || guideStep === 0) {
    elements.guideStepCount.textContent = "READY TO START";
    elements.guideProgressLabel.textContent = `Selected: ${guideScenarioLabels[guideAction]}`;
    elements.guideKicker.textContent = "THE MISSION";
    elements.guideTitle.textContent = "Stop a compromised agent before the wallet signs";
    elements.guideCopy.textContent = "Run one real local gateway evaluation, then use Next to reveal what happened at every security boundary.";
    setGuideEvidence({
      label: guideError ? "FAILED CLOSED" : "READY",
      value: guideError || `Run ${guideScenarioLabels[guideAction]}`,
      detail: guideError ? "No trusted result was rendered. Retry when the gateway is available." : "The result will be computed by the Python gateway and returned to this browser.",
      tone: guideError ? "block" : "",
      facts: [["Security engine", "Connected"], ["Settlement mode", "Simulation"], ["Next action", "POST selected scenario"]],
      source: "Awaiting gateway",
    });
    renderGuideFlow(null);
    elements.guideNext.textContent = `Run ${guideScenarioLabels[guideAction]}`;
    elements.guideNext.disabled = guideAutoRunning;
    return;
  }

  const event = guideState.events[0];
  const stage = guideStageContent(event, guideState.active_mandate);
  elements.guideStepCount.textContent = `STEP ${guideStep} OF ${guideNodeNames.length}`;
  elements.guideProgressLabel.textContent = guideNodeNames[guideStep - 1].replaceAll("_", " ").toUpperCase();
  elements.guideKicker.textContent = stage.kicker;
  elements.guideTitle.textContent = stage.title;
  elements.guideCopy.textContent = stage.copy;
  setGuideEvidence(stage.evidence);
  renderGuideFlow(event);
  elements.guideNext.textContent = guideStep === guideNodeNames.length ? "Open audit receipt" : "Next security boundary";
  elements.guideNext.disabled = guideAutoRunning;
}

function selectGuideAction(action) {
  guideAction = action;
  guideStep = 0;
  guideState = null;
  guideAudit = null;
  guideError = "";
  for (const button of guideScenarioButtons) {
    button.classList.toggle("selected", button.dataset.guideAction === action);
  }
  renderGuide();
}

async function executeGuideScenario() {
  guideError = "";
  elements.guideNext.disabled = true;
  elements.guideNext.textContent = "Running gateway...";
  guideScenarioButtons.forEach((button) => { button.disabled = true; });
  try {
    const response = await fetch(`/api/demo/${guideAction}`, { method: "POST" });
    if (!response.ok) throw new Error("Scenario failed safely");
    guideState = await response.json();
    const auditResponse = await fetch("/api/audit", { cache: "no-store" });
    guideAudit = auditResponse.ok ? await auditResponse.json() : null;
    guideStep = 1;
    renderState(guideState);
  } catch (error) {
    guideState = null;
    guideError = error instanceof Error ? error.message : "Scenario unavailable";
  } finally {
    renderGuide();
  }
}

async function advanceGuide() {
  if (!guideState) {
    await executeGuideScenario();
    return;
  }
  if (guideStep < guideNodeNames.length) {
    guideStep += 1;
    renderGuide();
    return;
  }
  elements.guidedDemo.close();
  await openAudit();
}

async function autoPlayGuide() {
  if (guideAutoRunning) {
    guideAutoRunning = false;
    renderGuide();
    return;
  }
  guideAutoRunning = true;
  renderGuide();
  if (!guideState) await executeGuideScenario();
  if (!guideState) {
    guideAutoRunning = false;
    renderGuide();
    return;
  }
  while (guideAutoRunning && guideStep < guideNodeNames.length) {
    await wait(1050);
    if (!guideAutoRunning) break;
    guideStep += 1;
    renderGuide();
  }
  guideAutoRunning = false;
  renderGuide();
}

function isIntegrityBlock(reasons) {
  return ["REQUEST_INVALID", "REQUEST_EXPIRED", "REQUEST_REPLAYED"].some((reason) =>
    reasons.has(reason),
  );
}

function setPipelineState(name, status, detail) {
  const step = pipelineSteps[name];
  step.className = `pipeline-step ${status}`;
  step.querySelector("small").textContent = detail;
}

function setGuardState(name, status) {
  const check = guardChecks[name];
  check.className = status;
  const symbol = check.querySelector("i");
  symbol.textContent = status === "block" ? "X" : status === "warn" ? "!" : status === "skipped" ? "-" : "\u2713";
}

function resetSecurityVisuals() {
  for (const name of Object.keys(pipelineSteps)) setPipelineState(name, "idle", "Waiting");
  for (const name of Object.keys(guardChecks)) setGuardState(name, "skipped");
}

function renderPipeline(event) {
  resetSecurityVisuals();
  if (!event) return;

  const reasons = new Set(event.reason_codes);
  const integrityBlocked = isIntegrityBlock(reasons);
  const policyBlocked = Array.from(reasons).some((reason) => reason.startsWith("POLICY_"));
  const detectionReasons = Array.from(reasons).filter((reason) => reason.startsWith("DETECTION_"));

  setPipelineState("normalize", "pass", "Normalized");
  if (integrityBlocked) {
    setPipelineState("integrity", "block", humanReason(event.reason_codes[0]));
    setPipelineState("mandate", "skipped", "Not evaluated");
    setPipelineState("behaviour", "skipped", "Not evaluated");
    setGuardState("integrity", "block");
    setGuardState("mandate", "skipped");
    setGuardState("behaviour", "skipped");
  } else {
    setPipelineState("integrity", "pass", "Fresh nonce");
    setPipelineState("mandate", policyBlocked ? "block" : "pass", policyBlocked ? "Hard block" : "Authorized");
    setGuardState("integrity", "pass");
    setGuardState("mandate", policyBlocked ? "block" : "pass");
    if (policyBlocked) {
      setPipelineState("behaviour", "skipped", "Not evaluated");
      setGuardState("behaviour", "skipped");
    } else if (detectionReasons.length === 0) {
      setPipelineState("behaviour", "pass", "Clean");
      setGuardState("behaviour", "pass");
    } else if (event.decision === "REQUIRE_APPROVAL") {
      setPipelineState("behaviour", "warn", "Flagged");
      setGuardState("behaviour", "warn");
    } else {
      setPipelineState("behaviour", "block", "Block signal");
      setGuardState("behaviour", "block");
    }
  }

  if (event.decision === "ALLOW") {
    setPipelineState("authorization", "pass", "Issued + consumed");
    setPipelineState("wallet", "pass", "Signed - simulated");
    setGuardState("authorization", "pass");
  } else if (event.decision === "REQUIRE_APPROVAL") {
    setPipelineState("authorization", "warn", "Approval required");
    setPipelineState("wallet", "withheld", "Not called");
    setGuardState("authorization", "warn");
  } else {
    setPipelineState("authorization", "withheld", "Withheld");
    setPipelineState("wallet", "withheld", "Not called");
    setGuardState("authorization", "block");
  }
}

function reachedPipeline(event) {
  const reasons = new Set(event.reason_codes);
  const reached = ["normalize", "integrity"];
  if (isIntegrityBlock(reasons)) return reached;
  reached.push("mandate");
  if (Array.from(reasons).some((reason) => reason.startsWith("POLICY_"))) return reached;
  reached.push("behaviour", "authorization");
  if (event.decision === "ALLOW") reached.push("wallet");
  return reached;
}

async function animatePipeline(event) {
  resetSecurityVisuals();
  for (const name of reachedPipeline(event)) {
    setPipelineState(name, "checking", "Evaluating");
    if (guardChecks[name]) {
      guardChecks[name].className = "checking";
      guardChecks[name].querySelector("i").textContent = "\u2022";
    }
    await wait(80);
  }
}

function renderScenario(state) {
  elements.scenarioName.textContent = scenarioLabels[state.active_scenario] || state.active_scenario.replaceAll("_", " ");
  for (const button of scenarioButtons) {
    button.classList.toggle("active", button.dataset.scenario === state.active_scenario);
  }
}

function renderReasonChips(event) {
  elements.reasonList.replaceChildren();
  if (!event.reason_codes.length) {
    elements.reasonList.append(textElement("span", "ALL CONTROLS PASSED", "reason-chip allow"));
    return;
  }
  const stateClass = decisionClass(event.decision);
  for (const reason of event.reason_codes) {
    elements.reasonList.append(textElement("span", humanReason(reason), `reason-chip ${stateClass}`));
  }
}

function renderDecisionSpotlight(state) {
  const event = state.events[0];
  renderPipeline(event);
  if (!event) {
    document.body.dataset.decision = "idle";
    elements.agentState.textContent = "READY";
    elements.decisionValue.textContent = "STANDBY";
    elements.decisionAmount.textContent = "Waiting for agent intent";
    elements.decisionRequest.textContent = "No request processed";
    elements.decisionLatency.textContent = "NO DATA";
    elements.decisionCopy.textContent = "Choose a scenario to send deterministic traffic through the real gateway.";
    elements.reasonList.replaceChildren(textElement("span", "NO DECISION YET", "reason-chip neutral"));
    elements.signerState.textContent = "WAITING";
    elements.signerDetail.textContent = "No payment evaluated";
    elements.settlementState.textContent = "NONE";
    elements.settlementDetail.textContent = "No settlement reference";
    elements.privacyState.textContent = "READY";
    elements.privacyDetail.textContent = "Sanitizer awaiting metadata";
    elements.receiptState.textContent = "WAITING";
    elements.receiptDetail.textContent = "No receipt generated";
    return;
  }

  const stateClass = decisionClass(event.decision);
  const redactions = redactionEvidence(event);
  document.body.dataset.decision = stateClass;
  elements.agentState.textContent = "REQUEST SUBMITTED";
  elements.decisionValue.textContent = decisionLabel(event.decision);
  elements.decisionAmount.textContent = `${event.amount} ${event.asset} -> ${event.recipient}`;
  elements.decisionRequest.textContent = `${event.request_id} - ${formatObservedAt(event.observed_at, true)}`;
  elements.decisionLatency.textContent = `${event.latency_ms} MS`;
  renderReasonChips(event);

  if (event.decision === "ALLOW") {
    elements.decisionCopy.textContent = "The request satisfied the mandate and security controls. A request-bound authorization reached the simulated wallet.";
  } else if (event.decision === "REQUIRE_APPROVAL") {
    elements.decisionCopy.textContent = "The request is plausible but anomalous. Settlement is paused for exceptional human review.";
  } else {
    elements.decisionCopy.textContent = "The request terminated before signing. The wallet balance remains protected.";
  }

  if (event.signing_state === "NOT_SIGNED") {
    elements.signerState.textContent = "NOT CALLED";
    elements.signerDetail.textContent = "No signing authorization reached the wallet";
  } else {
    elements.signerState.textContent = "SIGNED - SIMULATED";
    elements.signerDetail.textContent = "Request-bound authorization consumed";
  }

  if (event.settlement_reference === null) {
    elements.settlementState.textContent = "NO SETTLEMENT";
    elements.settlementDetail.textContent = "No settlement reference generated";
  } else {
    elements.settlementState.textContent = "SETTLED";
    elements.settlementDetail.textContent = shortDigest(event.settlement_reference, 24);
  }

  elements.privacyState.textContent = redactions.total === 0 ? "SAFE COPY" : `${redactions.total} REDACTED`;
  elements.privacyDetail.textContent = redactions.total === 0 ? "No supported sensitive pattern detected" : redactions.categories.join(" - ");
  elements.receiptState.textContent = "HASH-LINKED";
  elements.receiptDetail.textContent = shortDigest(event.receipt_digest, 24);
}

function addCell(row, value, className = "") {
  const cell = textElement("td", value, className);
  row.append(cell);
  return cell;
}

function renderTransactions(events) {
  elements.eventList.replaceChildren();
  if (events.length === 0) {
    const row = document.createElement("tr");
    const cell = addCell(row, "No payment requests processed yet.", "empty");
    cell.colSpan = 8;
    elements.eventList.append(row);
    return;
  }

  for (const event of events.slice(0, 8)) {
    const row = document.createElement("tr");
    addCell(row, formatObservedAt(event.observed_at));
    addCell(row, event.request_id);
    addCell(row, event.recipient);
    addCell(row, `${event.amount} ${event.asset}`);
    const decisionCell = document.createElement("td");
    decisionCell.append(textElement("span", decisionLabel(event.decision), `table-decision ${decisionClass(event.decision)}`));
    row.append(decisionCell);
    const reason = event.reason_codes.length ? event.reason_codes.map(humanReason).join(" / ") : "Controls passed";
    const reasonCell = addCell(row, reason);
    reasonCell.title = reason;
    addCell(row, event.signing_state === "NOT_SIGNED" ? "NOT CALLED" : "SIGNED", event.signing_state === "NOT_SIGNED" ? "signing-withheld" : "signing-safe");
    addCell(row, event.settlement_reference ? "SETTLED" : "N/A", event.settlement_reference ? "signing-safe" : "");
    elements.eventList.append(row);
  }
}

function renderState(state) {
  const counts = state.decision_counts;
  const mandate = state.active_mandate;
  elements.allowCount.textContent = String(counts.allowed);
  elements.approvalCount.textContent = String(counts.require_approval);
  elements.blockCount.textContent = String(counts.blocked);
  elements.protectedValue.textContent = `${state.value_protected} ${mandate.asset}`;
  elements.blockedContext.textContent = `Across ${counts.blocked} blocked request${counts.blocked === 1 ? "" : "s"}`;
  elements.walletBalance.textContent = `${state.wallet_balance} ${mandate.asset}`;
  elements.settlementType.textContent = state.settlement_type === "SIMULATED" ? "Local simulation" : state.settlement_type;
  const lastSettlement = state.events.find((event) => event.settlement_reference !== null);
  elements.lastSettlement.textContent = lastSettlement ? `${lastSettlement.amount} ${lastSettlement.asset} - Success` : "None";
  elements.mandateHeading.textContent = `${mandate.agent_id} - ${mandate.asset}`;
  elements.mandatePurpose.textContent = mandate.purpose;
  elements.mandateLimit.textContent = `${mandate.max_single_payment} ${mandate.asset}`;
  elements.mandateMode.textContent = mandate.policy_mode.replaceAll("_", " ");
  elements.mandateBlocked.textContent = mandate.blocked_recipients.length ? mandate.blocked_recipients.join(" - ") : "None";
  elements.mandateValidUntil.textContent = formatDate(mandate.valid_until);
  renderScenario(state);
  renderDecisionSpotlight(state);
  renderTransactions(state.events);
}

async function loadState() {
  const response = await fetch("/api/state", { cache: "no-store" });
  if (!response.ok) throw new Error("Gateway state unavailable");
  const state = await response.json();
  renderState(state);
  const indicator = document.createElement("i");
  indicator.setAttribute("aria-hidden", "true");
  elements.systemStatus.replaceChildren(indicator, document.createTextNode(" OPERATIONAL"));
  return state;
}

async function runAction(action) {
  if (isBusy) return;
  isBusy = true;
  buttons.forEach((button) => { button.disabled = true; });
  elements.actionStatus.classList.remove("error");
  const actionMessages = {
    approval: "Evaluating a first-seen recipient...",
    attack: "Compromised agent is attempting a drain...",
    normal: "Evaluating a normal API purchase...",
    replay: "Submitting the same request and nonce twice...",
    reset: "Resetting local runtime...",
  };
  elements.actionStatus.textContent = actionMessages[action] || "Evaluating payment...";
  try {
    const response = await fetch(`/api/demo/${action}`, { method: "POST" });
    if (!response.ok) throw new Error("Scenario failed safely");
    const state = await response.json();
    if (action !== "reset" && state.events[0]) await animatePipeline(state.events[0]);
    renderState(state);
    if (action === "reset") {
      elements.actionStatus.textContent = "Runtime reset - ready";
    } else if (action === "replay") {
      elements.actionStatus.textContent = "Duplicate nonce rejected before policy and signing";
    } else if (action === "approval") {
      elements.actionStatus.textContent = "First-seen recipient paused for exceptional review";
    } else if (state.events[0]?.decision === "BLOCK") {
      elements.actionStatus.textContent = "Drain stopped automatically before signing";
    } else {
      elements.actionStatus.textContent = "Normal payment passed the automated security boundary";
    }
  } catch (error) {
    elements.actionStatus.classList.add("error");
    elements.actionStatus.textContent = error instanceof Error ? error.message : "Scenario unavailable";
  } finally {
    isBusy = false;
    buttons.forEach((button) => { button.disabled = false; });
  }
}

function renderAudit(audit) {
  elements.auditChainState.textContent = audit.valid_chain ? "VALID HASH-LINKED CHAIN" : "CHAIN VERIFICATION FAILED";
  elements.auditChainState.style.color = audit.valid_chain ? "var(--green)" : "var(--red)";
  elements.auditRetained.textContent = `${audit.retained} receipt${audit.retained === 1 ? "" : "s"}`;
  elements.auditContent.replaceChildren();
  if (audit.events.length === 0) {
    elements.auditContent.append(textElement("p", "No receipts yet. Run a scenario to generate evidence."));
    return;
  }
  for (const event of [...audit.events].reverse()) {
    const card = document.createElement("article");
    card.className = `receipt-card ${decisionClass(event.decision)}`;
    card.append(textElement("span", decisionLabel(event.decision)));
    const details = document.createElement("div");
    details.append(textElement("strong", `${event.request_id} - ${event.amount} ${event.asset} -> ${event.recipient}`));
    const digest = textElement("code", event.receipt_digest);
    digest.title = event.receipt_digest;
    details.append(digest);
    details.append(textElement("small", event.reason_codes.length ? event.reason_codes.map(humanReason).join(" / ") : "All controls passed"));
    card.append(details);
    card.append(textElement("small", formatObservedAt(event.observed_at, true)));
    elements.auditContent.append(card);
  }
}

async function openAudit() {
  if (!elements.auditDialog.open) elements.auditDialog.showModal();
  elements.auditContent.replaceChildren(textElement("p", "Loading audit receipts..."));
  try {
    const response = await fetch("/api/audit", { cache: "no-store" });
    if (!response.ok) throw new Error("Audit stream unavailable");
    renderAudit(await response.json());
  } catch (error) {
    elements.auditContent.replaceChildren(textElement("p", error instanceof Error ? error.message : "Audit stream unavailable"));
  }
}

buttons.forEach((button) => {
  button.addEventListener("click", () => runAction(button.dataset.action));
});
guideScenarioButtons.forEach((button) => {
  button.addEventListener("click", () => selectGuideAction(button.dataset.guideAction));
});
document.getElementById("start-guided-demo").addEventListener("click", () => {
  selectGuideAction("attack");
  elements.guidedDemo.showModal();
});
document.getElementById("close-guided-demo").addEventListener("click", () => {
  guideAutoRunning = false;
  elements.guidedDemo.close();
});
elements.guidedDemo.addEventListener("close", () => {
  guideAutoRunning = false;
});
elements.guideBack.addEventListener("click", () => {
  if (guideStep > 0) guideStep -= 1;
  renderGuide();
});
elements.guideNext.addEventListener("click", advanceGuide);
elements.guideAuto.addEventListener("click", autoPlayGuide);
document.getElementById("open-audit").addEventListener("click", openAudit);
document.getElementById("open-audit-top").addEventListener("click", openAudit);

loadState().catch(() => {
  elements.actionStatus.classList.add("error");
  elements.actionStatus.textContent = "Gateway state unavailable";
  elements.systemStatus.textContent = "ENGINE UNAVAILABLE";
});

window.setInterval(() => {
  if (!isBusy && !elements.auditDialog.open) loadState().catch(() => undefined);
}, 2000);
