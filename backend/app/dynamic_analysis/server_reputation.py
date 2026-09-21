"""Module for checking suspicious domains and IP addresses against external reputation APIs (AbuseIPDB, VirusTotal)."""

import ipaddress
import logging
import os
import re
import time
from typing import Any, Dict, List, Union

import requests

logger = logging.getLogger("server_reputation")

# Regex for IPv4 address matching
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def is_ip_address(host: str) -> bool:
    """Checks whether a given host string is a valid IPv4 or IPv6 address."""
    clean_host = host.strip()
    if IPV4_REGEX.match(clean_host):
        return True
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Queries AbuseIPDB API v2 to check IP reputation if ABUSEIPDB_API_KEY is configured.
    Falls back to checking private/reserved IP ranges if API key is not present or query fails.

    :param ip: Target IPv4 or IPv6 address string.
    :return: Dict containing reputation data and verdict ('clean'|'suspicious'|'malicious'|'unverified').
    """
    clean_ip = ip.strip()

    # Local heuristic: check if IP is private/reserved
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return {
                "status": "skipped",
                "verdict": "clean",
                "reason": f"IP address '{clean_ip}' is in a private or reserved range.",
                "abuse_score": 0,
            }
    except ValueError:
        pass

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuse_key:
        return {
            "status": "skipped",
            "verdict": "unverified",
            "reason": "AbuseIPDB API key (ABUSEIPDB_API_KEY) is not configured in environment.",
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": abuse_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": clean_ip,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)

            if abuse_score >= 50:
                verdict = "malicious"
            elif abuse_score >= 25:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return {
                "status": "completed",
                "verdict": verdict,
                "abuse_score": abuse_score,
                "total_reports": data.get("totalReports", 0),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "country_code": data.get("countryCode"),
            }
        else:
            return {
                "status": "skipped",
                "verdict": "unverified",
                "reason": f"AbuseIPDB API returned HTTP {response.status_code}",
            }
    except Exception as exc:
        logger.warning(f"AbuseIPDB reputation query failed for '{clean_ip}': {exc}")
        return {
            "status": "skipped",
            "verdict": "unverified",
            "reason": f"AbuseIPDB query failed: {str(exc)}",
        }


def check_domain_reputation(domain: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 Domain API to check domain reputation if VT_API_KEY is configured.
    Falls back to unverified status if API key is not present or query fails.

    :param domain: Target domain string.
    :return: Dict containing reputation data and verdict ('clean'|'suspicious'|'malicious'|'unverified').
    """
    clean_domain = domain.strip().lower()
    # Remove protocol prefix if present
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://", 1)[1]
    if "/" in clean_domain:
        clean_domain = clean_domain.split("/", 1)[0]
    if ":" in clean_domain:
        clean_domain = clean_domain.split(":", 1)[0]

    vt_api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        return {
            "status": "skipped",
            "verdict": "unverified",
            "reason": "VirusTotal API key (VT_API_KEY) is not configured in environment.",
        }

    url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"
    headers = {"x-apikey": vt_api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious >= 1:
                verdict = "malicious"
            elif suspicious >= 1:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return {
                "status": "completed",
                "verdict": verdict,
                "stats": stats,
                "reputation_score": attributes.get("reputation", 0),
            }
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "verdict": "unverified",
                "reason": "Domain not found in VirusTotal database.",
            }
        else:
            return {
                "status": "skipped",
                "verdict": "unverified",
                "reason": f"VirusTotal API returned HTTP {response.status_code}",
            }
    except Exception as exc:
        logger.warning(f"VirusTotal domain reputation query failed for '{clean_domain}': {exc}")
        return {
            "status": "skipped",
            "verdict": "unverified",
            "reason": f"VirusTotal query failed: {str(exc)}",
        }


def check_all(hosts: List[Union[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Takes a list of suspected C2 hosts (strings or dictionaries containing 'host' key),
    separates IPs vs domains, runs reputation checks with basic rate limiting,
    and returns combined reputation results.

    :param hosts: List of host strings or dicts from C2 detection.
    :return: Dict containing 'checked' host list with verdicts.
    """
    # Note: Free-tier API keys for AbuseIPDB and VirusTotal have strict rate limits
    # (e.g. 4 requests/minute for VirusTotal). A time.sleep(1) pause is inserted
    # between external network requests. Demo analysis runs should use a small host count.

    checked: List[Dict[str, Any]] = []
    seen_hosts = set()

    for item in hosts:
        if isinstance(item, dict):
            host_str = str(item.get("host", "")).strip().lower()
        else:
            host_str = str(item).strip().lower()

        if not host_str or host_str in seen_hosts:
            continue

        seen_hosts.add(host_str)

        is_ip = is_ip_address(host_str)
        if is_ip:
            rep_result = check_ip_reputation(host_str)
            host_type = "ip"
        else:
            rep_result = check_domain_reputation(host_str)
            host_type = "domain"

        verdict = rep_result.get("verdict", "unverified")

        checked.append({
            "host": host_str,
            "type": host_type,
            "reputation": rep_result,
            "verdict": verdict,
        })

        # Rate-limiting backoff delay between host lookups
        time.sleep(1)

    return {"checked": checked}
