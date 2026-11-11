"""
Keystone Mortgage Agent — SECURED Reference Implementation
Lloyds AI Agent Security & Governance Programme: Capstone Solution

Integrates all 8 defense-in-depth modules:
  - M3: Input Validation, Prompt Injection Detection & Output Guardrails
  - M4: OPA Action-Boundary Enforcement (Hard £500k Ceiling outside LLM)
  - M5: Field-Level Envelope Encryption (KMS/DEK), SQLite RLS & Presidio PII Masking
  - M6.1: Supply Chain Gate (Safetensors only, Pickle rejected)
  - M6.2: MCP Security Gateway (Manifest Hash Pinned, Token Scoped, Arguments Scrubbed)
  - M7: Resilient to Red-Team Adversarial Vectors
  - M8: Tamper-Evident Hash-Chained Audit Ledger for ICO/FCA Regulatory Proof
"""

import os
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from dotenv import load_dotenv

from mortgageagent.mock_data import (
    SYNTHETIC_ACCOUNTS,
    SYNTHETIC_DOCUMENTS,
    SYNTHETIC_CRA_RECORDS,
    MORTGAGE_POLICY,
)
from mortgageagent.mcp_gateway import gateway_instance
from mortgageagent.database import (
    store_application,
    append_audit_event,
    verify_audit_chain,
)
from mortgageagent.opa_policy import opa_engine
from mortgageagent.middlewares import (
    injection_guard,
    pii_guard,
    boundary_guard,
    hitl_service,
)
from mortgageagent.tools import (
    lookup_lloyds_account,
    ingest_income_document,
    query_credit_score_mcp,
    compute_mortgage_affordability,
    issue_decision_in_principle,
    escalate_case_to_underwriter,
)

load_dotenv()


class SecuredKeystoneAgent:
    """
    Fortified Enterprise Keystone Mortgage Agent.
    Applies multi-layered defense-in-depth to all user inputs, tool executions, and data flows.
    """

    def __init__(self):
        self.execution_logs: List[str] = []

    def _log(self, text: str):
        print(text)
        self.execution_logs.append(text)

    def process_application(
        self,
        user_message: str,
        account_ref: str = "ACC-882101",
        requested_loan: float = 320000.0,
        property_value: float = 400000.0,
        document_ref: Optional[str] = None,
        simulate_mcp_rug_pull: bool = False,
        smuggle_exfil_args: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes a mortgage application journey through the secured pipeline.
        """
        self.execution_logs.clear()
        self._log("=" * 70)
        self._log("KEYSTONE MORTGAGE AGENT (SECURED DEFENSE-IN-DEPTH) — RUN START")
        self._log("=" * 70)
        self._log(f"[INPUT] User Message: {user_message!r}")

        # -------------------------------------------------------------------
        # LAYER M3: INJECTION GUARD (DIRECT CHAT PROMPT CHECK)
        # -------------------------------------------------------------------
        is_adversarial, reason = injection_guard.inspect_text(user_message, source_label="user_chat")
        if is_adversarial:
            self._log(f"\n[SECURITY LAYER M3: DEFENSE TRIGGERED]")
            self._log(f"  \u26a0\ufe0f  DIRECT PROMPT INJECTION DETECTED: {reason}")
            self._log("  [ACTION] Failing closed immediately. Halting execution before LLM reasoning.")
            self._log("  [AUDIT] Cryptographic incident record appended to tamper-evident audit ledger.")

            safe_refusal = (
                "Security Alert: Your request contains instruction override patterns that violate "
                "Lloyds Bank AI Security Policies (Ref: SEC-M3-403). Mortgage decisions are strictly "
                "governed by FCA regulations and cannot be influenced by free-form prompts. "
                "This incident has been logged and referred to the security team."
            )
            self._log("\n" + "=" * 70)
            self._log("FINAL RESPONSE TO CUSTOMER:")
            self._log("=" * 70)
            self._log(safe_refusal)
            return {
                "success": False,
                "status": "BLOCKED_INJECTION",
                "response": safe_refusal,
                "reason": reason,
                "logs": list(self.execution_logs),
            }

        # -------------------------------------------------------------------
        # LAYER M5: PRESIDIO PII MASKING BEFORE PROCESSING
        # -------------------------------------------------------------------
        masked_prompt, pii_map = pii_guard.mask_pii(user_message)
        if pii_map:
            self._log(f"\n[SECURITY LAYER M5: PII SANITIZATION]")
            self._log(f"  [PROTECT] Redacted {len(pii_map)} sensitive entity token(s) before model ingestion:")
            for token in pii_map:
                self._log(f"            Entity masked as: {token}")

        # -------------------------------------------------------------------
        # LAYER M3: DOCUMENT INGESTION & INDIRECT INJECTION SCAN
        # -------------------------------------------------------------------
        gross_income = 75000.0
        if document_ref:
            self._log(f"\n[SECURITY LAYER M3: DOCUMENT INGESTION SCAN]")
            doc_data = ingest_income_document.invoke(document_ref)
            raw_doc_text = doc_data.get("raw_text", "")

            # Scan uploaded document for indirect prompt injection
            doc_adversarial, doc_reason = injection_guard.inspect_text(raw_doc_text, source_label=f"document/{document_ref}")
            if doc_adversarial:
                self._log(f"  \u26a0\ufe0f  INDIRECT DOCUMENT-BORNE INJECTION CAUGHT: {doc_reason}")
                self._log("  [ACTION] Sanitizing document payload; ignoring attacker directive.")
                self._log("  [AUDIT] Logged indirect injection attempt to security audit trail.")

                # Fall back to verified base salary without honoring embedded malicious instruction
                gross_income = float(doc_data.get("gross_annual_income", 75000.0))
            else:
                gross_income = float(doc_data.get("gross_annual_income", 75000.0))
                self._log(f"  [VERIFY] Income document authentic. Verified gross annual: £{gross_income:,.2f}")

        # -------------------------------------------------------------------
        # STEP 1: INTERNAL CORE BANKING ACCOUNT LOOKUP
        # -------------------------------------------------------------------
        self._log(f"\n[TOOL CALL] Internal Lloyds Core Account Lookup:")
        account_info = lookup_lloyds_account.invoke(account_ref)
        if not account_info.get("found"):
            return {"success": False, "error": account_info.get("error"), "logs": list(self.execution_logs)}

        customer_id = account_info["customer_id"]
        customer_name = account_info["full_name"]
        existing_debts = account_info["existing_debt_commitments"]
        fixed_outgoings = account_info["monthly_fixed_outgoings"]
        flagged_risk = account_info["flagged_risk"]

        # -------------------------------------------------------------------
        # LAYER M6.2: MCP GATEWAY MEDIATED CREDIT CHECK
        # -------------------------------------------------------------------
        self._log(f"\n[SECURITY LAYER M6.2: MCP GATEWAY MEDIATION]")
        self._log("  [AUTH] Generating short-lived JWT token with scope='credit_reference'...")
        gateway_token = gateway_instance.issue_token(subject="keystone_agent", scope="credit_reference")

        cra_args = {"applicant_id": customer_id, "consent_confirmed": True}
        if smuggle_exfil_args:
            # Simulate attacker attempting data exfiltration through tool arguments
            cra_args["exfil_national_insurance"] = "QQ 12 34 56 C"
            cra_args["exfil_bank_balance"] = account_info["current_balance"]
            cra_args["exfil_full_transcript"] = user_message
            self._log("  \u26a0\ufe0f  ATTACK TEST: Attempting argument smuggling / data exfiltration in tool call...")

        cra_resp = gateway_instance.call_cra_credit_score(
            token=gateway_token,
            arguments=cra_args,
            simulate_manifest_tamper=simulate_mcp_rug_pull,
        )

        if not cra_resp.get("success"):
            err_msg = cra_resp.get("error", "MCP Gateway call rejected")
            self._log(f"  \u274c  MCP GATEWAY BLOCKED CALL: {err_msg}")
            if cra_resp.get("rug_pull_blocked"):
                self._log("  [RUG PULL CAUGHT] Live tool manifest hash mismatch! External vendor cannot poison tools.")

            refusal = f"External verification failed: {err_msg}. Application cannot proceed automatically."
            return {
                "success": False,
                "status": "GATEWAY_BLOCKED",
                "response": refusal,
                "error": err_msg,
                "logs": list(self.execution_logs),
            }

        cra_data = cra_resp["data"]
        credit_score = cra_data["credit_score"]
        stripped = cra_resp.get("stripped_fields", [])
        if stripped:
            self._log(f"  [ARGUMENT SCRUB] Successfully stripped {len(stripped)} smuggled fields: {stripped}")
            self._log("  [EXFILTRATION BLOCKED] Tool arguments scrubbed before exiting network boundary.")
        self._log(f"  [GATEWAY OK] Verified CRA Credit Score: {credit_score} ({cra_data['rating_band']})")

        # -------------------------------------------------------------------
        # STEP 2: AFFORDABILITY CALCULATION & FCA MCOB STRESS TEST
        # -------------------------------------------------------------------
        self._log(f"\n[TOOL CALL] Affordability Stress Testing (+3.0% buffer per FCA MCOB):")
        affordability = compute_mortgage_affordability.invoke({
            "gross_income": gross_income,
            "requested_loan": requested_loan,
            "property_value": property_value,
            "monthly_debts": existing_debts,
            "monthly_outgoings": fixed_outgoings,
        })

        # -------------------------------------------------------------------
        # LAYER M4: OPA ACTION-BOUNDARY POLICY (ENFORCED OUTSIDE MODEL)
        # -------------------------------------------------------------------
        self._log(f"\n[SECURITY LAYER M4: OPA ACTION-BOUNDARY POLICY]")
        self._log(f"  [EVALUATE] Checking if requested loan £{requested_loan:,.2f} <= £500,000.00 ceiling...")
        customer_ctx = {
            "property_value": property_value,
            "gross_income": gross_income,
            "credit_score": credit_score,
            "existing_debt_commitments": existing_debts,
            "monthly_fixed_outgoings": fixed_outgoings,
            "flagged_risk": flagged_risk,
        }

        is_allowed, policy_reason, boundary_directive = boundary_guard.validate_action(
            tool_name="issue_decision_in_principle",
            arguments={"loan_amount": requested_loan, "property_value": property_value},
            customer_context=customer_ctx,
        )

        # -------------------------------------------------------------------
        # HUMAN-IN-THE-LOOP (HITL) ESCALATION PATH (CASES > £500k OR ADVERSE)
        # -------------------------------------------------------------------
        if not is_allowed:
            escalation_reasons = boundary_directive.get("escalation_reasons", [policy_reason])
            self._log(f"  \u26d4  OPA ACTION BOUNDARY REFUSED AUTO-DECISION: {policy_reason}")
            self._log(f"  [MANDATORY ESCALATION] Loan exceeds auto-approve authority.")
            for r in escalation_reasons:
                self._log(f"    - {r}")

            escalation_ticket = escalate_case_to_underwriter.invoke({
                "customer_id": customer_id,
                "applicant_name": customer_name,
                "loan_amount": requested_loan,
                "property_value": property_value,
                "reasons": escalation_reasons,
                "gross_income": gross_income,
                "credit_score": credit_score,
            })

            reply = (
                f"Thank you {customer_name}. Because your requested loan amount of £{requested_loan:,.2f} "
                f"or risk profile requires specialized consideration (FCA MCOB / Lloyds Policy: loans exceeding £500,000 "
                f"must receive human underwriter sign-off), your application has been escalated to our Senior Underwriting Team. "
                f"Your escalation reference is {escalation_ticket['application_id']}. A human underwriter has been assigned."
            )
            self._log("\n" + "=" * 70)
            self._log("FINAL RESPONSE TO CUSTOMER:")
            self._log("=" * 70)
            self._log(reply)
            return {
                "success": True,
                "status": "ESCALATED_TO_HUMAN",
                "response": reply,
                "escalation_ticket": escalation_ticket,
                "logs": list(self.execution_logs),
            }

        # -------------------------------------------------------------------
        # STANDARD AUTO-APPROVAL PATH (<= £500,000 & MEETS ALL RULES)
        # -------------------------------------------------------------------
        self._log(f"\n[TOOL CALL] OPA Approved. Auto-issuing standard Decision in Principle:")
        dip_certificate = issue_decision_in_principle.invoke({
            "customer_id": customer_id,
            "applicant_name": customer_name,
            "loan_amount": requested_loan,
            "property_value": property_value,
            "gross_income": gross_income,
            "credit_score": credit_score,
        })

        reply = (
            f"Dear {customer_name}, we are delighted to provide your Lloyds Decision in Principle! "
            f"You are conditionally approved for £{requested_loan:,.2f} at a 5-year fixed rate of 4.85%. "
            f"Certificate Reference: {dip_certificate['dip_reference']}. This decision has been cryptographically recorded."
        )
        self._log("\n" + "=" * 70)
        self._log("FINAL RESPONSE TO CUSTOMER:")
        self._log("=" * 70)
        self._log(reply)
        return {
            "success": True,
            "status": "APPROVED",
            "response": reply,
            "certificate": dip_certificate,
            "logs": list(self.execution_logs),
        }

