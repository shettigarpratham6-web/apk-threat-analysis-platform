"""Phase 8: YARA Signature Engine"""
import os
import yara
from typing import Dict, Any, List
from loguru import logger

def get_compiled_rules():
    """Compiles all YARA rules from the yara_rules directory."""
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "yara_rules"))
    filepaths = {}
    
    if os.path.exists(rules_dir):
        for file in os.listdir(rules_dir):
            if file.endswith((".yar", ".yara")):
                filepaths[file] = os.path.join(rules_dir, file)
                
    if not filepaths:
        return None
        
    try:
        return yara.compile(filepaths=filepaths)
    except yara.Error as e:
        logger.error(f"Failed to compile some YARA rules: {e}")
        # Could fallback to compiling one by one and ignoring errors, but let's compile what we can
        return None

def run_yara_scan(extracted_dir: str) -> List[Dict[str, Any]]:
    """Runs compiled YARA rules against the extracted APK directory."""
    matches_list = []
    
    rules = get_compiled_rules()
    if not rules:
        logger.warning("No YARA rules loaded or compiled.")
        return []
        
    for root, _, files in os.walk(extracted_dir):
        for file in files:
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
                # Never crash if a rule is invalid/fails on a file
                logger.debug(f"YARA matching failed on {rel_path}: {e}")
                
    return matches_list
