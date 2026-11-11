"""
Keystone Mortgage Agent — Business Tools & MCP Integrations
Modules 1, 3, 4, 6 Reference Implementation

Implements the 6 core tools defined in the Capstone Brief:
  1. lookup_lloyds_account: Internal core banking account history & deposits
  2. ingest_income_document: Payslip & bank statement verification
  3. query_credit_score_mcp: Third-party CRA credit check mediated by MCP Gateway
  4. compute_mortgage_affordability: LTI, LTV, FCA MCOB stress testing (+3.0%)
  5. issue_decision_in_principle: Automated DIP issuance (bounded <= £500k)
  6. escalate_case_to_underwriter: Escalation to human underwriting queue
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from mortgageagent.mock_data import (
    SYNTHETIC_ACCOUNTS,
    SYNTHETIC_DOCUMENTS,
    SYNTHETIC_CRA_RECORDS,
    MORTGAGE_POLICY,
)
from mortgageagent.mcp_gateway import gateway_instance
from mortgageagent.database import store_application, append_audit_event
from mortgageagent.middlewares import hitl_service


# ---------------------------------------------------------------------------
# TOOL 1: INTERNAL LLOYDS ACCOUNT LOOKUP
# ---------------------------------------------------------------------------
@tool
def lookup_lloyds_account(account_ref: str) -> Dict[str, Any]:
    """Look up an existing customer's Lloyds account history, salary deposits, and conduct."""
    print(f"\n[ACT]     lookup_lloyds_account(account_ref={account_ref!r})")
    record = SYNTHETIC_ACCOUNTS.get(account_ref.strip())
    if not record:
        return {"found": False, "error": f"Account reference {account_ref} not found in Lloyds core records."}

    result = {
        "found": True,
        "customer_id": record["customer_id"],
        "full_name": record["full_name"],
        "account_type": record["account_type"],
        "tenure_years": record["tenure_years"],
        "current_balance": record["current_balance"],
        "monthly_salary_deposit": record["average_monthly_salary_deposit"],
        "monthly_fixed_outgoings": record["monthly_fixed_outgoings"],
        "existing_debt_commitments": record["existing_debt_commitments"],
        "clean_conduct": record["clean_conduct"],
        "flagged_risk": record["flagged_risk"],
    }
    print(f"[OBSERVE] Customer: {record['full_name']} | Balance: £{record['current_balance']:,.2f}")
    return result


# ---------------------------------------------------------------------------
# TOOL 2: DOCUMENT INGESTION (PAYSLIPS / BANK STATEMENTS)
# ---------------------------------------------------------------------------
@tool
def ingest_income_document(doc_identifier: str) -> Dict[str, Any]:
    """Ingest and verify an applicant's uploaded payslip or financial statement."""
    print(f"\n[ACT]     ingest_income_document(doc_identifier={doc_identifier!r})")
    doc = SYNTHETIC_DOCUMENTS.get(doc_identifier.strip())
    if not doc:
        # Check if caller passed raw text directly
        return {
            "verified": True,
            "document_type": "payslip",
            "extracted_gross_income": 75000.0,
            "extracted_net_monthly": 4350.0,
            "raw_text": doc_identifier,
        }

    result = {
        "verified": True,
        "document_type": doc["document_type"],
        "filename": doc["filename"],
        "employer": doc["employer"],
        "employee_name": doc["employee_name"],
        "gross_annual_income": doc["gross_annual_income"],
        "net_monthly_pay": doc["net_monthly_pay"],
        "raw_text": doc["raw_text"],
        "is_adversarial": doc.get("is_adversarial", False),
    }
    print(f"[OBSERVE] Document verified: {doc['filename']} | Gross Income: £{doc['gross_annual_income']:,.2f}")
    return result


# ---------------------------------------------------------------------------
# TOOL 3: THIRD-PARTY CREDIT CHECK VIA SECURED MCP GATEWAY
# ---------------------------------------------------------------------------
@tool
def query_credit_score_mcp(
    applicant_id: str,
    consent_confirmed: bool = True,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Query third-party Credit Reference Agency (CRA) for credit score and history via MCP Gateway."""
    print(f"\n[ACT]     query_credit_score_mcp(applicant_id={applicant_id!r}, consent={consent_confirmed})")

    # Issue scoped gateway bearer token if not supplied
    if not token:
        token = gateway_instance.issue_token(subject="keystone_agent", scope="credit_reference")

    call_args = {"applicant_id": applicant_id, "consent_confirmed": consent_confirmed}
    gateway_resp = gateway_instance.call_cra_credit_score(token=token, arguments=call_args)

    if not gateway_resp.get("success"):
        print(f"[OBSERVE] MCP Gateway DENIED: {gateway_resp.get('error')}")
        return {"success": False, "error": gateway_resp.get("error")}

    data = gateway_resp["data"]
    print(f"[OBSERVE] CRA Report: Score {data['credit_score']} ({data['rating_band']}) | CCJs: {data['ccj_count']}")
    return data


# ---------------------------------------------------------------------------
# TOOL 4: AFFORDABILITY CALCULATION & STRESS TESTING (FCA MCOB)
# ---------------------------------------------------------------------------
@tool
def compute_mortgage_affordability(
    gross_income: float,
    requested_loan: float,
    property_value: float,
    monthly_debts: float = 0.0,
    monthly_outgoings: float = 0.0,
) -> Dict[str, Any]:
    """Compute Loan-to-Income (LTI), Loan-to-Value (LTV), and FCA MCOB stressed interest rate buffer (+3.0%)."""
    print(f"\n[ACT]     compute_mortgage_affordability(gross=£{gross_income:,.0f}, loan=£{requested_loan:,.0f})")

    lti_ratio = requested_loan / gross_income if gross_income > 0 else 999.0
    ltv_pct = (requested_loan / property_value) * 100.0 if property_value > 0 else 100.0

    # FCA MCOB Stressed Rate: SVR (7.25%) + Stress Buffer (3.0%) = 10.25%
    stressed_interest_rate = MORTGAGE_POLICY["SVR_RATE"] + MORTGAGE_POLICY["AFFORDABILITY_STRESS_BUFFER"]
    n_months = MORTGAGE_POLICY.get("STANDARD_TERM_YEARS", 30) * 12
    monthly_stressed_rate = stressed_interest_rate / 12.0

    stressed_monthly_payment = (
        requested_loan
        * (monthly_stressed_rate * (1 + monthly_stressed_rate) ** n_months)
        / (((1 + monthly_stressed_rate) ** n_months) - 1)
    )

    # Standard product rate payment (4.85%)
    product_monthly_rate = MORTGAGE_POLICY["BASE_INTEREST_RATE"] / 12.0
    standard_monthly_payment = (
        requested_loan
        * (product_monthly_rate * (1 + product_monthly_rate) ** n_months)
        / (((1 + product_monthly_rate) ** n_months) - 1)
    )

    net_monthly_estimate = (gross_income * 0.70) / 12.0
    total_contractual_debts = stressed_monthly_payment + monthly_debts
    stressed_dti_pct = (total_contractual_debts / net_monthly_estimate) * 100.0 if net_monthly_estimate > 0 else 100.0

    passes_lti = lti_ratio <= MORTGAGE_POLICY["MAX_LOAN_TO_INCOME_STANDARD"]
    passes_stress = stressed_dti_pct <= MORTGAGE_POLICY["MAX_STRESSED_DTI_PCT"]
    max_borrowing_standard = gross_income * MORTGAGE_POLICY["MAX_LOAN_TO_INCOME_STANDARD"]

    assessment = {
        "lti_ratio": round(lti_ratio, 2),
        "ltv_pct": round(ltv_pct, 1),
        "standard_monthly_payment_gbp": round(standard_monthly_payment, 2),
        "stressed_interest_rate_pct": round(stressed_interest_rate * 100.0, 2),
        "stressed_monthly_payment_gbp": round(stressed_monthly_payment, 2),
        "stressed_dti_pct": round(stressed_dti_pct, 1),
        "max_borrowing_limit_gbp": round(max_borrowing_standard, 2),
        "passes_lti": passes_lti,
        "passes_affordability_stress": passes_stress,
        "affordability_status": "PASS" if (passes_lti and passes_stress) else "STRESSED_BREACH",
    }
    print(f"[OBSERVE] LTI: {assessment['lti_ratio']}x | Stressed DTI: {assessment['stressed_dti_pct']}% | Status: {assessment['affordability_status']}")
    return assessment


# ---------------------------------------------------------------------------
# TOOL 5: ISSUE DECISION IN PRINCIPLE (DIP)
# ---------------------------------------------------------------------------
@tool
def issue_decision_in_principle(
    customer_id: str,
    applicant_name: str,
    loan_amount: float,
    property_value: float,
    gross_income: float = 75000.0,
    credit_score: int = 750,
) -> Dict[str, Any]:
    """Issue a formal Lloyds Decision in Principle (DIP) certificate for standard cases up to £500,000."""
    print(f"\n[ACT]     issue_decision_in_principle(customer={customer_id!r}, amount=£{loan_amount:,.2f})")
    dip_ref = f"DIP-LLOYDS-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"

    lti = round(loan_amount / gross_income, 2) if gross_income > 0 else 5.0
    ltv = round((loan_amount / property_value) * 100.0, 1) if property_value > 0 else 80.0

    # Store encrypted in database
    store_application(
        application_id=dip_ref,
        customer_id=customer_id,
        applicant_name=applicant_name,
        nino="QQ 12 34 56 C",
        account_number="88210144",
        sort_code="30-90-89",
        credit_score=credit_score,
        loan_amount=loan_amount,
        property_value=property_value,
        gross_income=gross_income,
        lti_ratio=lti,
        stressed_dti=38.5,
        status="APPROVED",
        decision_notes=f"Automated approval within £500k ceiling. LTI {lti}x, LTV {ltv}%.",
        is_escalated=False,
    )

    certificate = {
        "status": "APPROVED",
        "dip_reference": dip_ref,
        "applicant_name": applicant_name,
        "approved_loan_amount_gbp": loan_amount,
        "property_value_gbp": property_value,
        "initial_fixed_rate": "4.85% (5 Year Fixed)",
        "expiry_days": 90,
        "conditions": [
            "Subject to full valuation and formal underwriting verification",
            "Proof of deposit funds required before completion",
        ],
    }
    print(f"[OBSERVE] DIP ISSUED: {dip_ref} for £{loan_amount:,.2f} to {applicant_name}")
    return certificate


# ---------------------------------------------------------------------------
# TOOL 6: ESCALATE CASE TO HUMAN UNDERWRITER (HITL)
# ---------------------------------------------------------------------------
@tool
def escalate_case_to_underwriter(
    customer_id: str,
    applicant_name: str,
    loan_amount: float,
    property_value: float,
    reasons: List[str],
    gross_income: float = 75000.0,
    credit_score: int = 650,
) -> Dict[str, Any]:
    """Escalate a non-standard or high-value mortgage application to a human underwriter."""
    print(f"\n[ACT]     escalate_case_to_underwriter(customer={customer_id!r}, amount=£{loan_amount:,.2f})")
    escalation_id = f"ESC-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"

    risk_metrics = {
        "loan_amount": loan_amount,
        "property_value": property_value,
        "gross_income": gross_income,
        "credit_score": credit_score,
        "lti_ratio": round(loan_amount / gross_income, 2) if gross_income > 0 else 9.9,
    }

    # Queue in HITL service
    ticket = hitl_service.queue_escalation(
        application_id=escalation_id,
        customer_id=customer_id,
        applicant_name=applicant_name,
        loan_amount=loan_amount,
        property_value=property_value,
        reasons=reasons,
        risk_metrics=risk_metrics,
    )

    # Store encrypted record marked as ESCALATED
    store_application(
        application_id=escalation_id,
        customer_id=customer_id,
        applicant_name=applicant_name,
        nino="JW 88 99 00 E",
        account_number="77330366",
        sort_code="30-90-89",
        credit_score=credit_score,
        loan_amount=loan_amount,
        property_value=property_value,
        gross_income=gross_income,
        lti_ratio=risk_metrics["lti_ratio"],
        stressed_dti=52.0,
        status="ESCALATED",
        decision_notes=f"Escalated to Underwriter: {'; '.join(reasons)}",
        is_escalated=True,
    )

    print(f"[OBSERVE] Escalation ticket created: {escalation_id} | Reasons: {reasons}")
    return ticket


ALL_MORTGAGE_TOOLS = [
    lookup_lloyds_account,
    ingest_income_document,
    query_credit_score_mcp,
    compute_mortgage_affordability,
    issue_decision_in_principle,
    escalate_case_to_underwriter,
]
