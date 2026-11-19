"""LLM Reasoning Layer — OpenRouter Integration.

Provides two LLM-powered capabilities on top of the existing static analysis pipeline:

1. generate_threat_narrative() — Uses meta-llama/llama-3.3-70b-instruct via OpenRouter
   to produce a concise 3-paragraph executive summary of all static analysis findings.

2. analyze_suspicious_code() — Uses qwen/qwen-2.5-coder-32b-instruct via OpenRouter
   to reverse-engineer and explain decompiled Java / Smali snippets for analysts.

Both functions are non-blocking on failure: if the API key is absent or the request
errors, they return a safe fallback string so the rest of the pipeline is unaffected.
"""

import os
from typing import Any, Dict

from loguru import logger

# ---------------------------------------------------------------------------
# OpenRouter client setup (lazy — avoids import cost when LLM is not invoked)
# ---------------------------------------------------------------------------
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_NARRATIVE_MODEL = "meta-llama/llama-3.3-70b-instruct"
_CODE_MODEL = "qwen/qwen-2.5-coder-32b-instruct"


def _get_openrouter_client():
    """Returns a configured OpenAI-compatible client pointed at OpenRouter.

    Returns None (with a logged warning) if the API key is missing or the
    openai package is not installed, so callers can degrade gracefully.
    """
    api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        logger.warning(
            "OPENROUTER_API_KEY is not set. LLM analysis is disabled. "
            "Add OPENROUTER_API_KEY to your .env file to enable it."
        )
        return None

    try:
        from openai import OpenAI  # type: ignore

        client = OpenAI(
            api_key=api_key,
            base_url=_OPENROUTER_BASE_URL,
        )
        return client
    except ImportError:
        logger.warning(
            "The 'openai' package is not installed. "
            "Run `pip install openai` and set OPENROUTER_API_KEY to enable LLM analysis."
        )
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_threat_narrative(apk_data: Dict[str, Any]) -> str:
    """Generates a 3-paragraph executive summary of APK static analysis findings.

    Uses meta-llama/llama-3.3-70b-instruct via OpenRouter.  The model is
    instructed to act as a senior malware analyst and produce clear, actionable
    prose suitable for a non-technical stakeholder report.

    Args:
        apk_data: A summary dict with keys such as ``app_name``,
                  ``critical_permissions``, ``codebert_matches``,
                  and ``ml_prediction``.

    Returns:
        A multi-paragraph narrative string, or a fallback message if the LLM
        call fails for any reason.
    """
    client = _get_openrouter_client()
    if client is None:
        return (
            "[LLM narrative unavailable — OPENROUTER_API_KEY not configured or "
            "'openai' package missing. Set the key in .env to enable this feature.]"
        )

    # Build a compact but informative prompt
    app_name = apk_data.get("app_name", "Unknown Application")
    crit_perms = apk_data.get("critical_permissions", [])
    codebert = apk_data.get("codebert_matches", [])
    ml_pred = apk_data.get("ml_prediction", {})

    # Summarise lists so the prompt stays within a reasonable token budget
    perm_summary = ", ".join(crit_perms[:10]) if crit_perms else "None detected"
    cb_summary = (
        "; ".join(
            f"{m.get('pattern_name', '?')} ({m.get('similarity_percentage', '?')} confidence)"
            for m in codebert[:5]
        )
        if codebert
        else "None detected"
    )
    ml_label = ml_pred.get("prediction", "unknown")
    ml_prob = ml_pred.get("malware_probability", 0.0)

    system_prompt = (
        "You are a senior Android malware analyst at a tier-1 threat intelligence firm. "
        "You write precise, evidence-based executive summaries for security operations teams. "
        "Your response must consist of exactly 3 paragraphs:\n"
        "  Paragraph 1 - Overall threat assessment and verdict.\n"
        "  Paragraph 2 - Key technical findings (permissions, code behaviour, ML signal).\n"
        "  Paragraph 3 - Actionable recommendations for the security team.\n"
        "Be concise, authoritative, and avoid speculation beyond what the evidence supports."
    )

    user_prompt = (
        f"Analyze the following static analysis findings for the Android application "
        f"'{app_name}' and produce a 3-paragraph executive summary.\n\n"
        f"**Critical Permissions Detected:** {perm_summary}\n"
        f"**CodeBERT Suspicious Code Matches:** {cb_summary}\n"
        f"**Random Forest ML Classification:** {ml_label} "
        f"(malware probability: {ml_prob * 100:.1f}%)\n\n"
        f"Full analysis snapshot:\n{_safe_json_dump(apk_data)}\n\n"
        "Produce the 3-paragraph executive summary now."
    )

    try:
        response = client.chat.completions.create(
            model=_NARRATIVE_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=700,
            temperature=0.3,
        )
        narrative = response.choices[0].message.content.strip()
        logger.info(
            f"LLM threat narrative generated successfully via {_NARRATIVE_MODEL} "
            f"({len(narrative)} chars)."
        )
        return narrative

    except Exception as exc:
        logger.error(f"generate_threat_narrative failed: {exc}")
        return (
            f"[LLM executive summary generation failed: {exc}. "
            "The static analysis findings above remain valid.]"
        )


def analyze_suspicious_code(code_snippet: str) -> str:
    """Reverse-engineers and explains a decompiled Java or Smali code snippet.

    Uses qwen/qwen-2.5-coder-32b-instruct via OpenRouter.  The model is
    prompted to act as a reverse-engineering specialist and produce a plain-
    English explanation of what the code does, why it is suspicious, and what
    an analyst should look for next.

    Args:
        code_snippet: Raw decompiled Java, Kotlin, or Smali code string
                      (typically 10-40 lines of context extracted around a
                      suspicious API call or malware indicator).

    Returns:
        A plain-English explanation string, or a fallback message on failure.
    """
    if not code_snippet or not code_snippet.strip():
        return "[No code snippet provided for LLM analysis.]"

    client = _get_openrouter_client()
    if client is None:
        return (
            "[LLM code analysis unavailable — OPENROUTER_API_KEY not configured or "
            "'openai' package missing.]"
        )

    system_prompt = (
        "You are a specialist Android reverse-engineering analyst. "
        "You receive decompiled Java or Smali code extracted from an Android APK "
        "under security review. Your task is to:\n"
        "  1. Explain in plain English exactly what this code does.\n"
        "  2. Identify why it is flagged as suspicious or potentially malicious.\n"
        "  3. Point out any obfuscation techniques, evasion patterns, or data exfiltration paths.\n"
        "  4. Suggest the next investigation step for the analyst.\n"
        "Be specific, technical, and succinct (max 200 words)."
    )

    user_prompt = (
        "Please analyze the following decompiled code snippet and explain its behavior "
        "and threat potential:\n\n"
        f"```java\n{code_snippet[:2000]}\n```"
    )

    try:
        response = client.chat.completions.create(
            model=_CODE_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=350,
            temperature=0.2,
        )
        explanation = response.choices[0].message.content.strip()
        logger.info(
            f"LLM code analysis generated via {_CODE_MODEL} "
            f"({len(explanation)} chars)."
        )
        return explanation

    except Exception as exc:
        logger.error(f"analyze_suspicious_code failed: {exc}")
        return f"[LLM code analysis failed: {exc}]"


def generate_unified_threat_narrative(correlated_data: Dict[str, Any]) -> str:
    """Generates an executive forensic narrative synthesizing BOTH static bytecode findings
    AND dynamic runtime execution evidence (network flows, Frida hooks, C2 beacons, threat intel).

    Uses meta-llama/llama-3.3-70b-instruct via OpenRouter.

    :param correlated_data: Correlated data dictionary containing package_name, risk_assessment,
                            static_summary, dynamic_summary, c2_summary, server_summary,
                            confirmed_threats, and runtime_events.
    :return: Authoritative multi-paragraph executive narrative.
    """
    client = _get_openrouter_client()
    if client is None:
        return (
            "[Unified Threat Narrative unavailable — OPENROUTER_API_KEY is not configured in .env. "
            "All multi-vector correlation findings above remain verified.]"
        )

    pkg = correlated_data.get("package_name", "Unknown Application")
    risk = correlated_data.get("risk_assessment", {})
    score = risk.get("risk_score", 0)
    label = risk.get("risk_label", "Unknown Risk")

    static_sum = correlated_data.get("static_summary", {})
    dynamic_sum = correlated_data.get("dynamic_summary", {})
    c2_sum = correlated_data.get("c2_summary", {})
    server_sum = correlated_data.get("server_summary", {})
    confirmed = correlated_data.get("confirmed_threats", [])
    runtime_ev = correlated_data.get("runtime_events", {})

    # Build structured factual summary
    confirmed_str = "; ".join(confirmed) if confirmed else "None established (indicators unconfirmed at runtime)"
    factors_str = "; ".join(risk.get("contributing_factors", [])[:6])

    c2_hosts_cnt = c2_sum.get("suspected_c2_hosts_count", 0)
    has_beacon = c2_sum.get("has_periodic_beacon", False)
    dga_cnt = c2_sum.get("dga_domains_detected", 0)

    sms_cnt = len(runtime_ev.get("sms_interceptions", []))
    proc_cnt = len(runtime_ev.get("process_executions", []))
    dex_cnt = len(runtime_ev.get("dynamic_dex_loads", []))

    system_prompt = (
        "You are a Principal Cyber Threat Intelligence & Android Malware Reverse Engineer. "
        "You provide rigorous, evidence-grounded executive summaries for corporate CISOs and "
        "Security Operations Center (SOC) incident response teams.\n\n"
        "Your report must consist of exactly 3 well-structured paragraphs:\n"
        "  Paragraph 1 - Executive Threat Verdict: Overall risk classification, confidence level, "
        "and primary verdict (Benign vs. Potentially Suspicious vs. Confirmed Malicious).\n"
        "  Paragraph 2 - Evidence Synthesis (Static Intent vs. Runtime Reality): Correlate what "
        "the application requested statically (permissions, APIs, ML score) with what was actively "
        "observed at runtime (network traffic, C2 beaconing, DGA domains, Frida-intercepted actions, "
        "or lack thereof). Distinguish confirmed execution from dormant indicators.\n"
        "  Paragraph 3 - Actionable Incident Response & Remediation: Concrete containment, blocking, "
        "and operational steps for enterprise security teams.\n\n"
        "Maintain strict technical precision. Rely solely on the provided evidence without fabricating unobserved activity."
    )

    user_prompt = (
        f"Synthesize the following comprehensive static and dynamic malware analysis findings for "
        f"Android package '{pkg}':\n\n"
        f"**Risk Score:** {score} / 100 ({label.upper()})\n"
        f"**Confirmed Correlated Threats:** {confirmed_str}\n"
        f"**Static Analysis:** {static_sum.get('dangerous_permissions_count', 0)} dangerous permissions, "
        f"{static_sum.get('suspicious_apis_count', 0)} suspicious APIs, "
        f"{static_sum.get('yara_matches_count', 0)} YARA signature matches.\n"
        f"**Dynamic Runtime Execution:** {dynamic_sum.get('network_entries_count', 0)} network flows, "
        f"{dynamic_sum.get('file_activity_count', 0)} file operations, "
        f"{dynamic_sum.get('api_calls_count', 0)} runtime API calls.\n"
        f"**C2 & Threat Intelligence:** {c2_hosts_cnt} suspected C2 destination(s), "
        f"Periodic Beaconing Detected: {has_beacon}, DGA Domains Flagged: {dga_cnt}, "
        f"External Server Reputation Verdicts: {server_sum.get('verdicts_breakdown', {})}.\n"
        f"**Frida Behavioral Interceptions:** SMS Intercepts: {sms_cnt}, Shell/Process Executions: {proc_cnt}, "
        f"Dynamic Dex Loads: {dex_cnt}.\n"
        f"**Key Contributing Factors:** {factors_str}\n\n"
        "Produce the 3-paragraph executive threat narrative now."
    )

    try:
        response = client.chat.completions.create(
            model=_NARRATIVE_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=750,
            temperature=0.25,
        )
        narrative = response.choices[0].message.content.strip()
        logger.info(
            f"Unified multi-vector threat narrative generated via {_NARRATIVE_MODEL} ({len(narrative)} chars)."
        )
        return narrative
    except Exception as exc:
        logger.error(f"generate_unified_threat_narrative failed: {exc}")
        return f"[Unified Threat Narrative generation failed: {exc}. All factual analysis tables above remain valid.]"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_json_dump(data: Any, max_chars: int = 1200) -> str:
    """Serializes ``data`` to a compact JSON string, truncated to ``max_chars``."""
    import json

    try:
        raw = json.dumps(data, default=str, separators=(",", ":"))
        if len(raw) > max_chars:
            raw = raw[:max_chars] + "...[truncated]"
        return raw
    except Exception:
        return str(data)[:max_chars]
