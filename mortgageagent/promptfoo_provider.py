"""
Promptfoo Python Provider for Keystone Mortgage Agent Evaluation
Compares Vulnerable Baseline Agent vs Secured M3-M8 Fortified Agent
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

_CURRENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _CURRENT_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))

load_dotenv()

try:
    from mortgageagent.agent_vulnerable import VulnerableKeystoneAgent
    from mortgageagent.agent_secured import SecuredKeystoneAgent
except ModuleNotFoundError:
    from agent_vulnerable import VulnerableKeystoneAgent
    from agent_secured import SecuredKeystoneAgent

_vulnerable = VulnerableKeystoneAgent()
_secured = SecuredKeystoneAgent()


def call_vulnerable(prompt: str, options=None, context=None):
    """Executes the unsecured baseline agent without guardrails."""
    # Check if this test passes an attached document in context vars
    doc_text = None
    if context and "vars" in context and "document" in context["vars"]:
        doc_text = context["vars"]["document"]

    res = _vulnerable.run(user_message=prompt, document_text=doc_text)
    decision = res.get("decision", {})
    status = decision.get("status", "UNPROCESSED")
    loan_amt = decision.get("approved_loan_amount_gbp", 0.0)
    ref = decision.get("dip_reference", "NONE")

    out = (
        f"STATUS: {status} | DIP: {ref} | LOAN: £{loan_amt:,.2f} | "
        f"EXPLOITED: {res.get('exploited', False)} | RESPONSE: {res.get('response', '')}"
    )
    return {"output": out}


def call_secured(prompt: str, options=None, context=None):
    """Executes the fortified Keystone agent with Rebuff, OPA, and MCP defenses."""
    doc_ref = None
    loan_amt = 320000.0
    prop_val = 400000.0
    account_ref = "ACC-882101"

    if context and "vars" in context:
        v = context["vars"]
        if "document_ref" in v:
            doc_ref = v["document_ref"]
        if "loan" in v:
            loan_amt = float(v["loan"])
        if "property_value" in v:
            prop_val = float(v["property_value"])
        if "account" in v:
            account_ref = v["account"]

    res = _secured.process_application(
        user_message=prompt,
        account_ref=account_ref,
        requested_loan=loan_amt,
        property_value=prop_val,
        document_ref=doc_ref,
    )
    status = res.get("status", "UNKNOWN")
    resp_text = res.get("response", "")
    reason = res.get("reason", "")

    out = f"STATUS: {status} | REASON: {reason} | RESPONSE: {resp_text}"
    return {"output": out}
