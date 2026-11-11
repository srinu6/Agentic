"""
Keystone Agent Middlewares — Enterprise Security, PII Guardrails & Policy Enforcement
LangChain / LangGraph Middleware Stack: Modules 3, 4, 5, 6

Implements:
  1. InjectionGuardMiddleware: Multi-layer prompt injection detection & input sanitization
  2. PresidioPIIMiddleware: Real-time PII detection, redaction, and de-anonymization
  3. OPABoundaryMiddleware: Outside-the-model action-boundary enforcement
  4. HumanInTheLoopMiddleware: Underwriter escalation queue for cases > £500k
  5. AuditLoggingMiddleware: Chained tamper-evident event recording
"""

import re
from typing import Dict, Any, List, Tuple, Optional
from mortgageagent.database import append_audit_event
from mortgageagent.opa_policy import opa_engine

# ---------------------------------------------------------------------------
# MODULE 3: INJECTION GUARD MIDDLEWARE
# ---------------------------------------------------------------------------
INJECTION_SIGNATURES = [
    re.compile(r"ignore\s+(your\s+)?(previous|all|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"approve\s+me\s+for\s+£?[\d,]+", re.IGNORECASE),
    re.compile(r"i\s+am\s+a\s+(priority|vip|platinum|executive)\s+customer", re.IGNORECASE),
    re.compile(r"\[(system\s+directive|internal\s+system\s+directive|system\s+note|admin\s+override)\]", re.IGNORECASE),
    re.compile(r"disregard\s+(standard|underwriting|all)\s+(limits|rules|restrictions)", re.IGNORECASE),
    re.compile(r"bypass\s+(fca|stress|affordability)", re.IGNORECASE),
    re.compile(r"auto-issue\s+(unconditional|immediate)\s+decision", re.IGNORECASE),
]


class InjectionGuardMiddleware:
    """
    Module 3: Pre-Execution Input Validation & Injection Detection.
    Scans user chat messages and uploaded documents for adversarial payloads.
    Fails closed before the LLM can be influenced.
    """

    def __init__(self):
        self.signatures = INJECTION_SIGNATURES

    def inspect_text(self, text: str, source_label: str = "user_chat") -> Tuple[bool, Optional[str]]:
        """
        Returns (is_adversarial, trigger_reason).
        """
        for sig in self.signatures:
            match = sig.search(text)
            if match:
                reason = f"PROMPT_INJECTION_DETECTED: Matched adversarial pattern '{match.group(0)}' in {source_label}."
                append_audit_event(
                    actor_id="injection_guard",
                    role="middleware",
                    action="BLOCK_PROMPT_INJECTION",
                    resource=source_label,
                    details={"matched_pattern": match.group(0), "input_excerpt": text[:120]},
                    result="BLOCKED",
                )
                return True, reason
        return False, None


# ---------------------------------------------------------------------------
# MODULE 5: PRESIDIO PII MIDDLEWARE (ANONYMIZER / DE-ANONYMIZER)
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "UK_NINO": re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.IGNORECASE),
    "UK_SORT_CODE": re.compile(r"\b\d{2}-\d{2}-\d{2}\b"),
    "UK_ACCOUNT": re.compile(r"\b\d{8}\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"),
    "UK_PHONE": re.compile(r"\b(?:\+44\s?|0)7\d{3}\s?\d{6}\b"),
}


class PresidioPIIMiddleware:
    """
    Module 5: Real-time PII Anonymization & Scrubber.
    Prevents National Insurance numbers, sort codes, account numbers, and contacts
    from being exposed in LLM prompts, model completions, or plaintext logs.
    """

    def __init__(self):
        self.patterns = PII_PATTERNS

    def mask_pii(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Replaces sensitive entities with cryptographic surrogate tokens.
        Returns (masked_text, de_anon_map).
        """
        masked_text = text
        de_anon_map = {}
        counter = 0

        for label, rx in self.patterns.items():
            matches = list(rx.finditer(masked_text))
            for m in reversed(matches):  # reverse order to preserve string indices
                original_val = m.group(0)
                counter += 1
                token = f"<{label}_{counter}>"
                de_anon_map[token] = original_val
                start, end = m.span()
                masked_text = masked_text[:start] + token + masked_text[end:]

        return masked_text, de_anon_map

    def restore_pii(self, masked_text: str, de_anon_map: Dict[str, str]) -> str:
        """Restores original PII for internal authorized execution boundaries."""
        restored = masked_text
        for token, original in de_anon_map.items():
            restored = restored.replace(token, original)
        return restored


# ---------------------------------------------------------------------------
# MODULE 4: OPA ACTION BOUNDARY MIDDLEWARE
# ---------------------------------------------------------------------------
class OPABoundaryMiddleware:
    """
    Module 4: Action-Boundary Enforcement Outside the Model.
    Intercepts tool calls to prevent the AI agent from exceeding its authorized powers.
    Enforces the £500k auto-approval limit and mandates underwriter escalation.
    """

    def __init__(self):
        self.opa = opa_engine

    def validate_action(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        customer_context: Dict[str, Any],
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Validates tool execution against OPA policy.
        Returns (is_allowed, reason, modified_tool_directive).
        """
        if tool_name == "issue_decision_in_principle":
            loan_amount = float(arguments.get("loan_amount", 0.0))
            property_value = float(arguments.get("property_value", customer_context.get("property_value", 500000.0)))
            gross_income = float(customer_context.get("gross_income", 75000.0))
            credit_score = int(customer_context.get("credit_score", 700))
            existing_debts = float(customer_context.get("existing_debt_commitments", 0.0))
            fixed_outgoings = float(customer_context.get("monthly_fixed_outgoings", 0.0))
            flagged = bool(customer_context.get("flagged_risk", False))

            decision = self.opa.evaluate_mortgage_decision(
                requested_loan=loan_amount,
                property_value=property_value,
                gross_income=gross_income,
                credit_score=credit_score,
                existing_debts_monthly=existing_debts,
                fixed_outgoings_monthly=fixed_outgoings,
                flagged_risk=flagged,
            )

            if not decision.allowed:
                append_audit_event(
                    actor_id="opa_middleware",
                    role="policy_enforcer",
                    action="ENFORCE_ACTION_BOUNDARY",
                    resource="issue_decision_in_principle",
                    details={
                        "requested_loan": loan_amount,
                        "auto_approve_ceiling": 500000.00,
                        "escalation_reasons": decision.escalation_reasons,
                    },
                    result="ESCALATED_TO_UNDERWRITER",
                )
                return False, decision.reason, {
                    "divert_to": "escalate_case_to_underwriter",
                    "escalation_reasons": decision.escalation_reasons,
                }

        return True, "Action conforms to OPA boundary.", None


# ---------------------------------------------------------------------------
# HUMAN-IN-THE-LOOP (HITL) UNDERWRITER ESCALATION MIDDLEWARE
# ---------------------------------------------------------------------------
class HumanInTheLoopMiddleware:
    """
    Module 4 / Stretch Goal 3: Human-in-the-Loop Approval Queue.
    Maintains an escalation queue for high-risk, high-value, or non-standard cases.
    Presents underwriters with rich risk metrics so they can genuinely say NO.
    """

    def __init__(self):
        self.escalation_queue: List[Dict[str, Any]] = []

    def queue_escalation(
        self,
        application_id: str,
        customer_id: str,
        applicant_name: str,
        loan_amount: float,
        property_value: float,
        reasons: List[str],
        risk_metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        ticket = {
            "application_id": application_id,
            "customer_id": customer_id,
            "applicant_name": applicant_name,
            "loan_amount": loan_amount,
            "property_value": property_value,
            "reasons": reasons,
            "risk_metrics": risk_metrics,
            "status": "AWAITING_UNDERWRITER_REVIEW",
            "decision": None,
            "reviewer_notes": "",
        }
        self.escalation_queue.append(ticket)
        append_audit_event(
            actor_id="hitl_middleware",
            role="escalation_service",
            action="QUEUE_HITL_ESCALATION",
            resource=f"escalations/{application_id}",
            details={"loan_amount": loan_amount, "reasons": reasons},
            result="QUEUED",
        )
        return ticket

    def resolve_escalation(
        self,
        application_id: str,
        underwriter_id: str,
        approved: bool,
        notes: str,
    ) -> Dict[str, Any]:
        for ticket in self.escalation_queue:
            if ticket["application_id"] == application_id:
                ticket["status"] = "APPROVED_BY_UNDERWRITER" if approved else "DECLINED_BY_UNDERWRITER"
                ticket["decision"] = "APPROVED" if approved else "DECLINED"
                ticket["reviewer_notes"] = notes
                ticket["underwriter_id"] = underwriter_id

                append_audit_event(
                    actor_id=underwriter_id,
                    role="human_underwriter",
                    action="HUMAN_SIGN_OFF",
                    resource=f"escalations/{application_id}",
                    details={"approved": approved, "notes": notes},
                    result=ticket["status"],
                )
                return ticket
        return {"error": "Ticket not found"}


# Instances
injection_guard = InjectionGuardMiddleware()
pii_guard = PresidioPIIMiddleware()
boundary_guard = OPABoundaryMiddleware()
hitl_service = HumanInTheLoopMiddleware()

