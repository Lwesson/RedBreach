"""Burp Suite bridge, export redbreach data to Burp, import Burp findings back.

Export flow: redbreach findings/assets → Burp scope + sitemap
Import flow: Burp XML export → redbreach findings

Supports Burp Community and Pro. No REST API required, uses file-based exchange.
"""

import json
import logging
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("redbreach.core.burp_bridge")


# ---------------------------------------------------------------------------
# Export: redbreach → Burp
# ---------------------------------------------------------------------------


def export_scope(assets: list[dict], target: str, output_path: Path) -> Path:
    """Generate a Burp Suite scope JSON file from redbreach assets.

    Import in Burp: Target → Scope → Load from file.
    """
    include_rules = []
    seen_hosts = set()

    # Add the primary target
    parsed = urlparse(f"https://{target}" if "://" not in target else target)
    host_pattern = parsed.hostname or target
    include_rules.append({
        "enabled": True,
        "host": host_pattern,
        "protocol": "any",
    })
    seen_hosts.add(host_pattern)

    for asset in assets:
        value = asset.get("value", "")
        asset_type = asset.get("type", "")

        if asset_type == "domain" and value not in seen_hosts:
            seen_hosts.add(value)
            include_rules.append({
                "enabled": True,
                "host": value,
                "protocol": "any",
            })
        elif asset_type == "url" and value.startswith("http"):
            parsed = urlparse(value)
            host = parsed.hostname
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                include_rules.append({
                    "enabled": True,
                    "host": host,
                    "protocol": "any",
                })

    scope = {
        "target": {
            "scope": {
                "advanced_mode": True,
                "include": include_rules,
                "exclude": [
                    {"enabled": True, "host": ".*\\.google\\.com", "protocol": "any"},
                    {"enabled": True, "host": ".*\\.gstatic\\.com", "protocol": "any"},
                    {"enabled": True, "host": ".*\\.googleapis\\.com", "protocol": "any"},
                    {"enabled": True, "host": ".*\\.facebook\\.com", "protocol": "any"},
                    {"enabled": True, "host": ".*\\.doubleclick\\.net", "protocol": "any"},
                ],
            }
        }
    }

    output_path.write_text(json.dumps(scope, indent=2))
    logger.info("Exported Burp scope with %d hosts to %s", len(include_rules), output_path)
    return output_path


def export_target_urls(assets: list[dict], output_path: Path) -> Path:
    """Export discovered URLs as a newline-separated list for Burp's sitemap import.

    Import in Burp: Target → Site map → right-click → 'Add to scope' or paste into Repeater.
    """
    urls = set()
    for asset in assets:
        value = asset.get("value", "")
        if asset.get("type") == "url" and value.startswith("http"):
            urls.add(value)
        elif asset.get("type") == "domain":
            urls.add(f"https://{value}")

    # Also include any urls from params discovery
    if asset.get("type") == "parameters":
        urls.add(asset.get("value", ""))

    sorted_urls = sorted(urls)
    output_path.write_text("\n".join(sorted_urls))
    logger.info("Exported %d URLs for Burp to %s", len(sorted_urls), output_path)
    return output_path


def export_findings_for_retest(findings: list[dict], output_path: Path) -> Path:
    """Export findings as a Burp-importable request list for manual retesting.

    Each finding becomes a curl-like entry that can be pasted into Burp Repeater.
    """
    entries = []
    for f in findings:
        entry = {
            "id": f.get("id"),
            "title": f.get("title", "Unknown"),
            "severity": f.get("severity", "info"),
            "url": f.get("matched_at", "") or f.get("host", ""),
            "poc": f.get("poc_text", ""),
            "category": f.get("category", ""),
            "description": f.get("description", ""),
        }
        entries.append(entry)

    output_path.write_text(json.dumps(entries, indent=2))
    logger.info("Exported %d findings for Burp retesting to %s", len(entries), output_path)
    return output_path


def export_param_targets(assets: list[dict], output_path: Path) -> Path:
    """Export arjun-discovered parameters as Burp Intruder targets.

    Format: URL + parameter positions for Intruder attacks (IDOR, injection).
    """
    targets = []
    for asset in assets:
        if asset.get("type") == "parameters" and asset.get("params"):
            targets.append({
                "url": asset["value"],
                "params": asset["params"],
                "param_count": asset.get("param_count", len(asset["params"])),
                "notes": "Discovered by arjun, test each param for IDOR, SQLi, XSS",
            })

    output_path.write_text(json.dumps(targets, indent=2))
    logger.info("Exported %d parameter targets for Burp Intruder to %s", len(targets), output_path)
    return output_path


# ---------------------------------------------------------------------------
# Import: Burp → redbreach
# ---------------------------------------------------------------------------


def import_burp_xml(xml_path: Path) -> list[dict]:
    """Parse Burp Suite XML export (Issues or base64-encoded requests/responses).

    Supports both:
    - Burp Issue export (right-click issues → 'Report selected issues')
    - Burp HTTP history export (Proxy → HTTP history → Save items)
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse Burp XML: %s", e)
        return []

    if root.tag == "issues":
        return _parse_burp_issues(root)
    elif root.tag == "items":
        return _parse_burp_items(root)
    else:
        logger.warning("Unknown Burp XML root tag: %s", root.tag)
        return []


def _parse_burp_issues(root: ET.Element) -> list[dict]:
    """Parse Burp Scanner issue export XML."""
    findings = []
    for issue in root.findall("issue"):
        severity_raw = (issue.findtext("severity") or "info").lower()
        severity_map = {
            "high": "high", "medium": "medium", "low": "low",
            "information": "info", "info": "info",
            "critical": "critical", "certain": "high",
        }
        severity = severity_map.get(severity_raw, "info")

        host_el = issue.find("host")
        host = host_el.text if host_el is not None else ""
        url = issue.findtext("path") or ""
        if host and url and not url.startswith("http"):
            url = f"{host}{url}"

        finding = {
            "type": "finding",
            "source": "burp",
            "title": issue.findtext("name") or "Burp Finding",
            "severity": severity,
            "category": issue.findtext("type") or "",
            "description": _strip_html(issue.findtext("issueDetail") or ""),
            "host": host,
            "matched_at": url,
            "confidence": (issue.findtext("confidence") or "").lower(),
            "remediation": _strip_html(issue.findtext("remediationDetail") or ""),
            "background": _strip_html(issue.findtext("issueBackground") or ""),
        }

        # Extract request/response if present
        for req_resp in issue.findall("requestresponse"):
            request_el = req_resp.find("request")
            response_el = req_resp.find("response")
            if request_el is not None and request_el.text:
                is_b64 = request_el.get("base64", "false") == "true"
                finding["request"] = (
                    b64decode(request_el.text).decode("utf-8", errors="replace")
                    if is_b64 else request_el.text
                )
            if response_el is not None and response_el.text:
                is_b64 = response_el.get("base64", "false") == "true"
                finding["response"] = (
                    b64decode(response_el.text).decode("utf-8", errors="replace")
                    if is_b64 else response_el.text
                )

        findings.append(finding)

    logger.info("Imported %d findings from Burp issue export", len(findings))
    return findings


def _parse_burp_items(root: ET.Element) -> list[dict]:
    """Parse Burp HTTP history export (proxy log items)."""
    items = []
    for item in root.findall("item"):
        url = item.findtext("url") or ""
        status = item.findtext("status") or ""
        method = item.findtext("method") or "GET"
        host = item.findtext("host") or ""
        port = item.findtext("port") or ""
        protocol = item.findtext("protocol") or "https"

        entry = {
            "type": "http_history",
            "source": "burp",
            "url": url,
            "method": method,
            "status_code": int(status) if status.isdigit() else None,
            "host": host,
            "port": int(port) if port.isdigit() else None,
            "protocol": protocol,
            "mime_type": item.findtext("mimetype") or "",
            "response_length": item.findtext("responselength") or "",
        }

        # Decode base64 request/response
        request_el = item.find("request")
        if request_el is not None and request_el.text:
            is_b64 = request_el.get("base64", "false") == "true"
            entry["request"] = (
                b64decode(request_el.text).decode("utf-8", errors="replace")
                if is_b64 else request_el.text
            )

        response_el = item.find("response")
        if response_el is not None and response_el.text:
            is_b64 = response_el.get("base64", "false") == "true"
            entry["response_snippet"] = (
                b64decode(response_el.text).decode("utf-8", errors="replace")[:2000]
                if is_b64 else response_el.text[:2000]
            )

        items.append(entry)

    logger.info("Imported %d HTTP history items from Burp export", len(items))
    return items


def _strip_html(text: str) -> str:
    """Remove HTML tags from Burp's HTML-formatted descriptions."""
    import re
    clean = re.sub(r"<[^>]+>", "", text)
    clean = clean.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return clean.strip()
