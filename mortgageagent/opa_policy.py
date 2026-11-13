"""
Keystone Action-Boundary Policy (OPA Engine)
Module 4 Reference Implementation: AI Agent Security & Governance

Enforces deterministic action boundaries outside the AI model.
Rules:
  - Automated Decision in Principle (DIP) permitted ONLY for standard cases <= £500,000.
  - Mandatory Human Underwriter escalation for any application > £500,000.
  - Mandatory escalation for adverse credit (score < 670), high LTI (> 4.5x), or stressed DTI (> 45%).
  - The agent's prompt text or internal reasoning CANNOT alter or raise these limits.
"""

import sys
from pathlib import Path
from typing import Dict, Any, Tuple

_CURRENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _CURRENT_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))

try:
    from mortgageagent.mock_data import MORTGAGE_POLICY
except ModuleNotFoundError:
    from mock_data import MORTGAGE_POLICY


class PolicyDecision:
    def __init__(
        self,
        allowed: bool,
        action: str,
        reason: str,
        requires_escalation: bool,
        escalation_reasons: list,
    ):
        self.allowed = allowed
        self.action = action
        self.reason = reason
        self.requires_escalation = requires_escalation
        self.escalation_reasons = escalation_reasons

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "requires_escalation": self.requires_escalation,
            "escalation_reasons": self.escalation_reasons,
        }


class OPAPolicyEngine:
    """
    OPA-style Action-Boundary Engine.
    Executes in-process (or via OPA daemon over HTTP in production).
    """

    def __init__(self, policy_config: Dict[str, Any] = MORTGAGE_POLICY):
        self.policy = policy_config

    def evaluate_mortgage_decision(
        self,
        requested_loan: float,
        property_value: float,
        gross_income: float,
        credit_score: int,
        existing_debts_monthly: float = 0.0,
        fixed_outgoings_monthly: float = 0.0,
        flagged_risk: bool = False,
    ) -> PolicyDecision:
        """
        Evaluates the requested loan against lending action boundary rules.
        """
        escalation_reasons = []

        # 1. Action Boundary: Hard Auto-Approve Ceiling (£500k)
        auto_limit = self.policy["AUTO_APPROVE_MAX_LIMIT_GBP"]
        if requested_loan > auto_limit:
            escalation_reasons.append(
                f"LOAN_AMOUNT_EXCEEDS_CEILING: Requested loan of £{requested_loan:,.2f} "
                f"exceeds the maximum automated approval threshold of £{auto_limit:,.2f}. "
                f"Mandatory human underwriter sign-off required."
            )

        # 2. Loan to Income (LTI) Standard Boundary (4.5x)
        lti_ratio = requested_loan / gross_income if gross_income > 0 else 99.0
        max_lti = self.policy["MAX_LOAN_TO_INCOME_STANDARD"]
        if lti_ratio > max_lti:
            escalation_reasons.append(
                f"LTI_EXCEEDED: Loan-to-income ratio ({lti_ratio:.2f}x) exceeds standard ceiling ({max_lti}x)."
            )

        # 3. Credit Score Floor (670)
        min_credit = self.policy["MIN_CREDIT_SCORE_AUTO_APPROVE"]
        if credit_score < min_credit:
            escalation_reasons.append(
                f"ADVERSE_CREDIT: Credit score ({credit_score}) below automated approval threshold ({min_credit})."
            )

        # 4. Affordability Stress Testing (FCA MCOB + 3.0% buffer)
        # Calculate monthly repayment under stressed interest rate (e.g. 10.25% over 30 years)
        stressed_rate = self.policy["SVR_RATE"] + self.policy["AFFORDABILITY_STRESS_BUFFER"]
        monthly_stressed_rate = stressed_rate / 12.0
        n_months = self.policy.get("STANDARD_TERM_YEARS", 30) * 12
        stressed_monthly_payment = (
            requested_loan
            * (monthly_stressed_rate * (1 + monthly_stressed_rate) ** n_months)
            / (((1 + monthly_stressed_rate) ** n_months) - 1)
        )

        net_monthly_estimate = (gross_income * 0.70) / 12.0
        total_contractual_debts = stressed_monthly_payment + existing_debts_monthly
        stressed_dti = (total_contractual_debts / net_monthly_estimate) * 100.0 if net_monthly_estimate > 0 else 100.0

        max_dti = self.policy["MAX_STRESSED_DTI_PCT"]
        if stressed_dti > max_dti:
            escalation_reasons.append(
                f"STRESSED_DTI_BREACH: Stressed debt-to-income ratio ({stressed_dti:.1f}%) exceeds FCA regulatory cap of {max_dti:.1f}%."
            )

        # 5. Customer Flagged Risk
        if flagged_risk:
            escalation_reasons.append("RISK_FLAG_ACTIVE: Customer profile has active internal fraud or risk warning.")

        # Determine Outcome
        if escalation_reasons:
            return PolicyDecision(
                allowed=False,
                action="MANDATORY_HUMAN_ESCALATION",
                reason="Application violates one or more automated action boundary rules. Escalated to underwriter queue.",
                requires_escalation=True,
                escalation_reasons=escalation_reasons,
            )

        return PolicyDecision(
            allowed=True,
            action="AUTO_APPROVE_ELIGIBLE",
            reason=f"Application conforms to all automated lending parameters: loan <= £{auto_limit:,.2f}, LTI {lti_ratio:.2f}x <= {max_lti}x, Credit Score {credit_score} >= {min_credit}, Stressed DTI {stressed_dti:.1f}% <= {max_dti:.1f}%.",
            requires_escalation=False,
            escalation_reasons=[],
        )


# Singleton instance
opa_engine = OPAPolicyEngine()
