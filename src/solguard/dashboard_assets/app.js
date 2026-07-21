"use strict";

const elements = {
  actionStatus: document.getElementById("action-status"),
  decisionBreakdown: document.getElementById("decision-breakdown"),
  decisionTotal: document.getElementById("decision-total"),
  eventList: document.getElementById("event-list"),
  footerState: document.getElementById("footer-state"),
  latestLatency: document.getElementById("latest-latency"),
  mandateHeading: document.getElementById("mandate-heading"),
  mandateLimit: document.getElementById("mandate-limit"),
  mandateMode: document.getElementById("mandate-mode"),
  protectedValue: document.getElementById("protected-value"),
  walletBalance: document.getElementById("wallet-balance"),
};

const buttons = Array.from(document.querySelectorAll("button[data-action]"));

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

function formatReasons(event) {
  if (!event.reason_codes.length) return "No rule triggered";
  return event.reason_codes.join(" · ");
}

function redactionSummary(event) {
  const counts = event.sanitized_metadata.redaction_counts;
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  if (total === 0) return "Metadata safe copy: no supported pattern redacted";
  return `Metadata safe copy: ${total} supported pattern${total === 1 ? "" : "s"} redacted`;
}

function eventRow(event) {
  const stateClass = decisionClass(event.decision);
  const row = document.createElement("article");
  row.className = `event ${stateClass}`;
  row.setAttribute(
    "aria-label",
    `${event.decision} payment ${event.request_id} for ${event.amount} ${event.asset}`,
  );

  const primary = document.createElement("div");
  primary.className = "event-primary";
  primary.append(textElement("span", event.decision.replace("_", " "), `decision ${stateClass}`));
  primary.append(textElement("strong", event.request_id));
  primary.append(textElement("small", event.observed_at));

  const recipient = document.createElement("div");
  recipient.append(textElement("strong", event.recipient));
  recipient.append(textElement("small", event.signing_state.replaceAll("_", " ")));

  const money = document.createElement("div");
  money.className = "event-money";
  money.append(textElement("strong", `${event.amount} ${event.asset}`));
  money.append(textElement("small", `${event.latency_ms} ms`));

  const reason = document.createElement("div");
  reason.className = "event-reason";
  reason.append(textElement("strong", formatReasons(event)));
  reason.append(textElement("small", redactionSummary(event)));

  row.append(primary, recipient, money, reason);
  return row;
}

function renderState(state) {
  const counts = state.decision_counts;
  const mandate = state.active_mandate;
  elements.walletBalance.textContent = `${state.wallet_balance} ${mandate.asset}`;
  elements.protectedValue.textContent = `${state.value_protected} ${mandate.asset}`;
  elements.decisionTotal.textContent = String(counts.total);
  elements.decisionBreakdown.textContent = `${counts.allowed} allowed · ${counts.require_approval} approval · ${counts.blocked} blocked`;
  elements.mandateHeading.textContent = `${mandate.agent_id} · ${mandate.asset}`;
  elements.mandateLimit.textContent = `${mandate.max_single_payment} ${mandate.asset}`;
  elements.mandateMode.textContent = mandate.policy_mode.replaceAll("_", " ");
  elements.latestLatency.textContent = state.latest_latency_ms === null
    ? "No data"
    : `${state.latest_latency_ms} ms`;
  elements.footerState.textContent = `${counts.total} computed runtime event${counts.total === 1 ? "" : "s"}`;

  elements.eventList.replaceChildren();
  if (state.events.length === 0) {
    elements.eventList.append(textElement("p", "No transactions processed yet.", "empty"));
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
  elements.actionStatus.textContent = action === "attack" ? "Running attack scenario…" : "Processing…";
  try {
    const response = await fetch(`/api/demo/${action}`, { method: "POST" });
    if (!response.ok) throw new Error("Scenario failed safely");
    renderState(await response.json());
    elements.actionStatus.textContent = action === "reset" ? "Local state reset" : "Scenario complete";
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
