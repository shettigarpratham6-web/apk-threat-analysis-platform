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

# In-memory cache for IP and domain reputation lookups (avoids duplicate API queries)
_REPUTATION_CACHE: Dict[str, Dict[str, Any]] = {}



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

    if clean_ip in _REPUTATION_CACHE:
        return _REPUTATION_CACHE[clean_ip]

    # Local heuristic: check if IP is private/reserved
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            res = {
                "status": "skipped",
                "verdict": "clean",
                "reason": f"IP address '{clean_ip}' is in a private or reserved range.",
                "abuse_score": 0,
            }
            _REPUTATION_CACHE[clean_ip] = res
            return res
    except ValueError:
        pass

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuse_key:
        res = {
            "status": "skipped",
            "verdict": "unverified",
            "reason": "AbuseIPDB API key (ABUSEIPDB_API_KEY) is not configured in environment.",
        }
        _REPUTATION_CACHE[clean_ip] = res
        return res

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
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)

            if abuse_score >= 50:
                verdict = "malicious"
            elif abuse_score >= 25:
                verdict = "suspicious"
            else:
                verdict = "clean"

            res = {
                "status": "completed",
                "verdict": verdict,
                "abuse_score": abuse_score,
                "total_reports": data.get("totalReports", 0),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "country_code": data.get("countryCode"),
            }
            _REPUTATION_CACHE[clean_ip] = res
            return res
        else:
            res = {
                "status": "skipped",
                "verdict": "unverified",
                "reason": f"AbuseIPDB API returned HTTP {response.status_code}",
            }
            _REPUTATION_CACHE[clean_ip] = res
            return res
    except Exception as exc:
        logger.warning(f"AbuseIPDB reputation query failed for '{clean_ip}': {exc}")
        res = {
            "status": "skipped",
            "verdict": "unverified",
            "reason": f"AbuseIPDB query failed: {str(exc)}",
        }
        _REPUTATION_CACHE[clean_ip] = res
        return res


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

    if clean_domain in _REPUTATION_CACHE:
        return _REPUTATION_CACHE[clean_domain]

    vt_api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        res = {
            "status": "skipped",
            "verdict": "unverified",
            "reason": "VirusTotal API key (VT_API_KEY) is not configured in environment.",
        }
        _REPUTATION_CACHE[clean_domain] = res
        return res

    url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"
    headers = {"x-apikey": vt_api_key}

    try:
        response = requests.get(url, headers=headers, timeout=5)
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

            res = {
                "status": "completed",
                "verdict": verdict,
                "stats": stats,
                "reputation_score": attributes.get("reputation", 0),
            }
            _REPUTATION_CACHE[clean_domain] = res
            return res
        elif response.status_code == 404:
            res = {
                "status": "not_found",
                "verdict": "unverified",
                "reason": "Domain not found in VirusTotal database.",
            }
            _REPUTATION_CACHE[clean_domain] = res
            return res
        else:
            res = {
                "status": "skipped",
                "verdict": "unverified",
                "reason": f"VirusTotal API returned HTTP {response.status_code}",
            }
            _REPUTATION_CACHE[clean_domain] = res
            return res
    except Exception as exc:
        logger.warning(f"VirusTotal domain reputation query failed for '{clean_domain}': {exc}")
        res = {
            "status": "skipped",
            "verdict": "unverified",
            "reason": f"VirusTotal query failed: {str(exc)}",
        }
        _REPUTATION_CACHE[clean_domain] = res
        return res


def check_all(hosts: List[Union[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Takes a list of suspected C2 hosts (strings or dictionaries containing 'host' key),
    separates IPs vs domains, runs reputation checks with adaptive rate limiting,
    and returns combined reputation results.

    :param hosts: List of host strings or dicts from C2 detection.
    :return: Dict containing 'checked' host list with verdicts.
    """
    checked: List[Dict[str, Any]] = []
    seen_hosts = set()

    # Limit to top 15 unique hosts to guarantee snappy response times
    unique_candidates = []
    for item in hosts:
        if isinstance(item, dict):
            host_str = str(item.get("host", "")).strip().lower()
        else:
            host_str = str(item).strip().lower()

        if host_str and host_str not in seen_hosts:
            seen_hosts.add(host_str)
            unique_candidates.append(host_str)
            if len(unique_candidates) >= 15:
                break

    for host_str in unique_candidates:
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

        # Only apply rate-limiting pause when an actual external API call was made
        if rep_result.get("status") == "completed":
            time.sleep(0.5)

    return {"checked": checked}
