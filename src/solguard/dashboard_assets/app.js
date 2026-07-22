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
