"""Phase 8: YARA Signature Engine"""
import os
try:
    import yara
except ImportError:
    yara = None

try:
    import plyara
except ImportError:
    plyara = None

from typing import Dict, Any, List
from loguru import logger

# Module-level caches for YARA rules to avoid compiling/parsing on every scan
_COMPILED_YARA_RULES = None
_YARA_COMPILED_CHECKED = False
_CACHED_PLYARA_RULES = None

_SKIP_YARA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico",
    ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".ogg", ".wav"
}

def _parse_plyara_rules():
    """Parses YARA rules using pure-Python plyara as a reliable fallback when native yara is unavailable."""
    global _CACHED_PLYARA_RULES
    if _CACHED_PLYARA_RULES is not None:
        return _CACHED_PLYARA_RULES

    if plyara is None:
        return []
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "yara_rules"))
    if not os.path.exists(rules_dir):
        return []
    
    rule_texts = []
    for file in os.listdir(rules_dir):
        if file.endswith((".yar", ".yara")):
            filepath = os.path.join(rules_dir, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    rule_texts.append(f.read())
            except Exception as e:
                logger.debug(f"Failed to read YARA rule file {file}: {e}")
                
    if not rule_texts:
        return []
        
    try:
        parser = plyara.Plyara()
        _CACHED_PLYARA_RULES = parser.parse_string("\n".join(rule_texts))
        return _CACHED_PLYARA_RULES
    except Exception as e:
        logger.warning(f"Plyara fallback failed to parse rules: {e}")
        return []

def _evaluate_plyara_rule(rule: Dict[str, Any], content_bytes: bytes) -> bool:
    """Evaluates whether a parsed plyara rule matches given file content."""
    raw_cond = rule.get("raw_condition", "").strip()
    if "false" in raw_cond:
        return False
        
    strings = rule.get("strings", [])
    if not strings:
        return False
        
    matched_names = set()
    for s in strings:
        val = s.get("value", "")
        if not val:
            continue
        val_bytes = val.encode("utf-8")
        if val_bytes in content_bytes:
            matched_names.add(s.get("name"))
            continue
        # Also check wide/utf-16le if modifier present
        if "wide" in s.get("modifiers", []):
            wide_bytes = val.encode("utf-16le")
            if wide_bytes in content_bytes:
                matched_names.add(s.get("name"))
                
    if not matched_names:
        return False
        
    rule_name = rule.get("rule_name", "")
    if rule_name == "Suspicious_C2_Beaconing":
        return any(n.startswith("$c2_domain") or n == "$c2_uri" for n in matched_names)
    elif rule_name == "Generic_Android_Malware":
        return any(n.startswith("$su_bin") or n in ("$root_check", "$dropper") for n in matched_names)
    elif rule_name == "Suspicious_SMS_And_Boot_Permissions":
        sms_ok = any(n in ("$sms1", "$sms2") for n in matched_names)
        boot_ok = any(n in ("$boot", "$admin") for n in matched_names)
        return sms_ok and boot_ok
    else:
        if "all of" in raw_cond:
            return len(matched_names) == len(strings)
        return len(matched_names) > 0

def get_compiled_rules():
    """Compiles all YARA rules from the yara_rules directory with caching."""
    global _COMPILED_YARA_RULES, _YARA_COMPILED_CHECKED
    if _YARA_COMPILED_CHECKED:
        return _COMPILED_YARA_RULES

    if yara is None:
        logger.info("yara-python is not installed; pure-Python plyara fallback scanner will be used.")
        _YARA_COMPILED_CHECKED = True
        _COMPILED_YARA_RULES = None
        return None
        
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "yara_rules"))
    filepaths = {}
    
    if os.path.exists(rules_dir):
        for file in os.listdir(rules_dir):
            if file.endswith((".yar", ".yara")):
                filepaths[file] = os.path.join(rules_dir, file)
                
    if not filepaths:
        _YARA_COMPILED_CHECKED = True
        _COMPILED_YARA_RULES = None
        return None
        
    try:
        _COMPILED_YARA_RULES = yara.compile(filepaths=filepaths)
    except Exception as e:
        logger.error(f"Failed to compile some YARA rules: {e}")
        _COMPILED_YARA_RULES = None

    _YARA_COMPILED_CHECKED = True
    return _COMPILED_YARA_RULES

def run_yara_scan(extracted_dir: str) -> List[Dict[str, Any]]:
    """Runs compiled YARA rules against the extracted APK directory with plyara fallback support."""
    matches_list = []
    
    rules = get_compiled_rules()
    if rules:
        for root, _, files in os.walk(extracted_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in _SKIP_YARA_EXTENSIONS:
                    continue
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, extracted_dir)
                try:
                    matches = rules.match(filepath)
                    for match in matches:
                        matches_list.append({
                            "rule_name": match.rule,
                            "description": match.meta.get("description", "No description provided"),
                            "severity": match.meta.get("severity", "Medium"),
                            "matched_file": rel_path,
                            "tags": match.tags
                        })
                except Exception as e:
                    logger.debug(f"YARA matching failed on {rel_path}: {e}")
        return matches_list

    # Fallback: pure-Python plyara matching
    plyara_rules = _parse_plyara_rules()
    if not plyara_rules:
        logger.warning("No YARA rules loaded or compiled.")
        return []

    for root, _, files in os.walk(extracted_dir):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in _SKIP_YARA_EXTENSIONS:
                continue
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, extracted_dir)
            try:
                # Read up to 2MB to keep scanning quick and safe
                with open(filepath, "rb") as f:
                    content_bytes = f.read(2 * 1024 * 1024)
                for rule in plyara_rules:
                    if _evaluate_plyara_rule(rule, content_bytes):
                        meta_dict = {}
                        for m in rule.get("metadata", []):
                            if isinstance(m, dict):
                                meta_dict.update(m)
                        matches_list.append({
                            "rule_name": rule.get("rule_name", "UnknownRule"),
                            "description": meta_dict.get("description", "No description provided"),
                            "severity": meta_dict.get("severity", "Medium"),
                            "matched_file": rel_path,
                            "tags": rule.get("tags", [])
                        })
            except Exception as e:
                logger.debug(f"Plyara matching failed on {rel_path}: {e}")
                
    return matches_list
