"use strict";

const elements = {
  actionStatus: document.getElementById("action-status"),
  decisionAmount: document.getElementById("decision-amount"),
  decisionBreakdown: document.getElementById("decision-breakdown"),
  decisionCopy: document.getElementById("decision-copy"),
  decisionLatency: document.getElementById("decision-latency"),
  decisionRequest: document.getElementById("decision-request"),
  decisionTotal: document.getElementById("decision-total"),
  decisionValue: document.getElementById("decision-value"),
  eventList: document.getElementById("event-list"),
  footerState: document.getElementById("footer-state"),
  mandateHeading: document.getElementById("mandate-heading"),
  mandateBlocked: document.getElementById("mandate-blocked"),
  mandateLimit: document.getElementById("mandate-limit"),
  mandateMode: document.getElementById("mandate-mode"),
  mandatePurpose: document.getElementById("mandate-purpose"),
  privacyDetail: document.getElementById("privacy-detail"),
  privacyState: document.getElementById("privacy-state"),
  protectedValue: document.getElementById("protected-value"),
  reasonList: document.getElementById("reason-list"),
  receiptDetail: document.getElementById("receipt-detail"),
  receiptState: document.getElementById("receipt-state"),
  scenarioName: document.getElementById("scenario-name"),
  settlementDetail: document.getElementById("settlement-detail"),
  settlementState: document.getElementById("settlement-state"),
  signerDetail: document.getElementById("signer-detail"),
  signerState: document.getElementById("signer-state"),
  walletBalance: document.getElementById("wallet-balance"),
};

const buttons = Array.from(document.querySelectorAll("button[data-action]"));
const scenarioButtons = Array.from(document.querySelectorAll("button[data-scenario]"));
const pipelineSteps = Object.fromEntries(
  Array.from(document.querySelectorAll("[data-pipeline]")).map((element) => [
    element.dataset.pipeline,
    element,
  ]),
);

const scenarioLabels = {
  COMPOUND_DRAIN: "SCENARIO 04 · COMPOUND WALLET DRAIN",
  NEW_RECIPIENT: "SCENARIO 02 · FIRST-SEEN RECIPIENT",
  NORMAL_PAYMENT: "SCENARIO 01 · NORMAL API PURCHASE",
  READY: "LIVE SCENARIO",
  REPLAY_ATTACK: "SCENARIO 03 · REPLAYED REQUEST",
};

const reasonLabels = {
  DETECTION_AMOUNT_ANOMALY: "AMOUNT AT LEAST 8× BASELINE",
  DETECTION_COMPOUND_DRAIN: "COMPOUND DRAIN PATTERN",
  DETECTION_RECIPIENT_NOVEL: "FIRST-SEEN RECIPIENT",
  DETECTION_VELOCITY: "HIGH PAYMENT VELOCITY",
  POLICY_AMOUNT_LIMIT: "MANDATE LIMIT EXCEEDED",
  POLICY_RECIPIENT_BLOCKED: "RECIPIENT HARD-BLOCKED",
  POLICY_RECIPIENT_NOT_ALLOWED: "RECIPIENT NOT ALLOWED",
  REQUEST_EXPIRED: "REQUEST EXPIRED",
  REQUEST_REPLAYED: "NONCE REPLAY DETECTED",
  SYSTEM_FAILURE: "SECURITY DEPENDENCY FAILED",
};

function textElement(tag, value, className = "") {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
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

function formatReasons(event) {
  if (!event.reason_codes.length) return "Mandate and security controls passed";
  return event.reason_codes.map(humanReason).join(" · ");
}

function redactionEvidence(event) {
  const counts = event.sanitized_metadata.redaction_counts;
  const entries = Object.entries(counts).filter(([, count]) => count > 0);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  return {
    categories: entries.map(([category]) => category.replaceAll("_", " ")),
    total,
  };
}

function shortDigest(value, visible = 18) {
  if (!value) return "None";
  return value.length > visible ? `${value.slice(0, visible)}…` : value;
}

function formatObservedAt(value) {
  const observed = new Date(value);
  if (Number.isNaN(observed.getTime())) return value;
  return `${observed.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
  })} UTC`;
}

function setPipelineState(name, status, detail) {
  const step = pipelineSteps[name];
  step.className = `pipeline-step ${status}`;
  step.querySelector("small").textContent = detail;
}

function renderPipeline(event) {
  for (const name of Object.keys(pipelineSteps)) setPipelineState(name, "idle", "Waiting");
  if (!event) return;

  const reasons = new Set(event.reason_codes);
  const integrityBlocked = ["REQUEST_INVALID", "REQUEST_EXPIRED", "REQUEST_REPLAYED"]
    .some((reason) => reasons.has(reason));
  const policyBlocked = Array.from(reasons).some((reason) => reason.startsWith("POLICY_"));
  const detectionReasons = Array.from(reasons).filter((reason) => reason.startsWith("DETECTION_"));

  setPipelineState("normalize", "pass", "CANONICALIZED");
  if (integrityBlocked) {
    setPipelineState("integrity", "block", humanReason(event.reason_codes[0]));
    setPipelineState("mandate", "skipped", "NOT EVALUATED");
    setPipelineState("behaviour", "skipped", "NOT EVALUATED");
  } else {
    setPipelineState("integrity", "pass", "FRESH NONCE");
    setPipelineState("mandate", policyBlocked ? "block" : "pass", policyBlocked ? "HARD BLOCK" : "WITHIN MANDATE");
    if (detectionReasons.length === 0) {
      setPipelineState("behaviour", "pass", "CLEAN");
    } else if (event.decision === "REQUIRE_APPROVAL") {
      setPipelineState("behaviour", "warn", "FLAGGED");
    } else {
      setPipelineState("behaviour", "block", "BLOCK SIGNAL");
    }
  }

  if (event.decision === "ALLOW") {
    setPipelineState("authorization", "pass", "ISSUED + CONSUMED");
    setPipelineState("wallet", "pass", "SIGNED · SIMULATED");
  } else {
    setPipelineState("authorization", "withheld", "WITHHELD");
    setPipelineState("wallet", "withheld", "NOT CALLED");
  }
}

function renderScenario(state) {
  elements.scenarioName.textContent = scenarioLabels[state.active_scenario] || state.active_scenario.replaceAll("_", " ");
  for (const button of scenarioButtons) {
    button.classList.toggle("active", button.dataset.scenario === state.active_scenario);
  }
}

function eventRow(event) {
  const stateClass = decisionClass(event.decision);
  const row = document.createElement("article");
  row.className = `event ${stateClass}`;
  row.setAttribute(
    "aria-label",
    `${event.decision} payment ${event.request_id} for ${event.amount} ${event.asset}`,
  );

  const sequence = document.createElement("div");
  sequence.className = "event-sequence";
  sequence.append(textElement("small", `REQUEST ${String(event.sequence).padStart(2, "0")}`));
  sequence.append(textElement("strong", event.request_id));

  const status = document.createElement("div");
  status.className = "event-status";
  status.append(textElement("span", decisionLabel(event.decision), `decision ${stateClass}`));
  status.append(textElement("small", formatObservedAt(event.observed_at)));

  const target = document.createElement("div");
  target.className = "event-target";
  target.append(textElement("strong", event.recipient));
  target.append(textElement("small", `${event.amount} ${event.asset} · ${event.latency_ms} ms`));

  const enforcement = document.createElement("div");
  enforcement.className = "event-enforcement";
  enforcement.append(textElement("strong", event.signing_state.replaceAll("_", " ")));
  enforcement.append(textElement("small", formatReasons(event)));

  row.append(sequence, status, target, enforcement);
  return row;
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
    elements.decisionValue.textContent = "STANDBY";
    elements.decisionAmount.textContent = "Waiting for agent intent";
    elements.decisionRequest.textContent = "No request processed";
    elements.decisionLatency.textContent = "NO DATA";
    elements.decisionCopy.textContent = "Run a normal payment or trigger the compromised-agent sequence to create live security evidence.";
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
  elements.decisionValue.textContent = decisionLabel(event.decision);
  elements.decisionAmount.textContent = `${event.amount} ${event.asset} → ${event.recipient}`;
  elements.decisionRequest.textContent = `${event.request_id} · ${formatObservedAt(event.observed_at)}`;
  elements.decisionLatency.textContent = `${event.latency_ms} MS`;
  renderReasonChips(event);

  if (event.decision === "ALLOW") {
    elements.decisionCopy.textContent = "The request satisfied the mandate and security controls. A request-bound authorization reached the simulated wallet boundary.";
  } else if (event.decision === "REQUIRE_APPROVAL") {
    elements.decisionCopy.textContent = "The request was plausible but anomalous. No authorization was issued and settlement is paused for explicit approval.";
  } else {
    elements.decisionCopy.textContent = "The request terminated before signing. No authorization reached the wallet and no settlement was created.";
  }

  if (event.signing_state === "NOT_SIGNED") {
    elements.signerState.textContent = "NOT CALLED";
    elements.signerDetail.textContent = "No signing authorization reached the wallet";
  } else {
    elements.signerState.textContent = "SIGNED · SIMULATED";
    elements.signerDetail.textContent = "Request-bound authorization consumed";
  }

  if (event.settlement_reference === null) {
    elements.settlementState.textContent = "NO SETTLEMENT";
    elements.settlementDetail.textContent = "No settlement reference generated";
  } else {
    elements.settlementState.textContent = "SETTLED · SIMULATED";
    elements.settlementDetail.textContent = shortDigest(event.settlement_reference, 24);
  }

  if (redactions.total === 0) {
    elements.privacyState.textContent = "SAFE COPY";
    elements.privacyDetail.textContent = "No supported sensitive pattern detected";
  } else {
    elements.privacyState.textContent = `${redactions.total} REDACTED`;
    elements.privacyDetail.textContent = redactions.categories.join(" · ");
  }

  elements.receiptState.textContent = "HASH-LINKED";
  elements.receiptDetail.textContent = shortDigest(event.receipt_digest, 24);
}

function renderState(state) {
  const counts = state.decision_counts;
  const mandate = state.active_mandate;
  elements.walletBalance.textContent = `${state.wallet_balance} ${mandate.asset}`;
  elements.protectedValue.textContent = `${state.value_protected} ${mandate.asset}`;
  elements.decisionTotal.textContent = String(counts.total);
  elements.decisionBreakdown.textContent = `${counts.allowed} allowed · ${counts.require_approval} approval · ${counts.blocked} blocked`;
  elements.mandateHeading.textContent = `${mandate.agent_id} · ${mandate.asset}`;
  elements.mandatePurpose.textContent = mandate.purpose;
  elements.mandateLimit.textContent = `${mandate.max_single_payment} ${mandate.asset}`;
  elements.mandateMode.textContent = mandate.policy_mode.replaceAll("_", " ");
  elements.mandateBlocked.textContent = mandate.blocked_recipients.length
    ? mandate.blocked_recipients.join(" · ")
    : "None";
  elements.footerState.textContent = `${counts.total} computed runtime event${counts.total === 1 ? "" : "s"}`;
  renderScenario(state);
  renderDecisionSpotlight(state);

  elements.eventList.replaceChildren();
  if (state.events.length === 0) {
    elements.eventList.append(textElement("p", "No payment requests processed yet.", "empty"));
    return;
  }
  for (const event of state.events) elements.eventList.append(eventRow(event));
}

async function loadState() {
  const response = await fetch("/api/state", { cache: "no-store" });
  if (!response.ok) throw new Error("Gateway state unavailable");
  renderState(await response.json());
}

async function runAction(action) {
  buttons.forEach((button) => { button.disabled = true; });
  elements.actionStatus.classList.remove("error");
  const actionMessages = {
    approval: "Evaluating a first-seen recipient…",
    attack: "Compromised agent is attempting a drain…",
    normal: "Evaluating a normal API purchase…",
    replay: "Submitting the same request and nonce twice…",
    reset: "Resetting local runtime…",
  };
  elements.actionStatus.textContent = actionMessages[action] || "Evaluating payment…";
  try {
    const response = await fetch(`/api/demo/${action}`, { method: "POST" });
    if (!response.ok) throw new Error("Scenario failed safely");
    const state = await response.json();
    renderState(state);
    if (action === "reset") {
      elements.actionStatus.textContent = "Runtime reset · ready";
    } else if (action === "replay") {
      elements.actionStatus.textContent = "Duplicate nonce rejected before policy and signing";
    } else if (action === "approval") {
      elements.actionStatus.textContent = "First-seen recipient paused for explicit approval";
    } else if (state.events[0]?.decision === "BLOCK") {
      elements.actionStatus.textContent = "Drain stopped before signing";
    } else {
      elements.actionStatus.textContent = "Normal payment allowed through the simulated boundary";
    }
  } catch (error) {
    elements.actionStatus.classList.add("error");
    elements.actionStatus.textContent = error instanceof Error ? error.message : "Scenario unavailable";
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}

buttons.forEach((button) => {
  button.addEventListener("click", () => runAction(button.dataset.action));
});

loadState().catch(() => {
  elements.actionStatus.classList.add("error");
  elements.actionStatus.textContent = "Gateway state unavailable";
});

window.setInterval(() => {
  loadState().catch(() => undefined);
}, 1500);
