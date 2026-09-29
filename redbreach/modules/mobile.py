"""Mobile (Android APK) static analysis.

Not part of the URL-oriented scan pipeline; driven by `redbreach mobile <app.apk>`.
Uses apktool (manifest + resources) and jadx (decompiled Java) which are on PATH,
then runs pure analyzers so the logic is unit-testable without an APK.
"""
from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path

from redbreach.core.subprocess_runner import run_tool
from redbreach.secrets import scan_secrets

logger = logging.getLogger("redbreach.modules.mobile")

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_URL_RE = re.compile(r"https?://[A-Za-z0-9._-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?")


def _finding(category: str, severity: str, title: str, description: str, source: str = "AndroidManifest.xml") -> dict:
    return {
        "type": "finding",
        "title": title,
        "severity": severity,
        "category": category,          # maps to CWE via redbreach.cwe
        "host": source,
        "matched_at": source,
        "description": description,
    }


def analyze_manifest(manifest_xml: str) -> list[dict]:
    """Flag insecure AndroidManifest.xml settings. Pure; takes decoded XML text."""
    import xml.etree.ElementTree as ET

    findings: list[dict] = []
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError:
        logger.debug("manifest not well-formed XML; skipping structural checks")
        return findings

    app = root.find("application")
    if app is None:
        return findings

    if app.get(_ANDROID_NS + "debuggable") == "true":
        findings.append(_finding(
            "debuggable", "high", "App is debuggable in production",
            "android:debuggable=\"true\" ships debug code and allows a local attacker to attach a debugger.",
        ))
    if app.get(_ANDROID_NS + "allowBackup") == "true":
        findings.append(_finding(
            "backup_allowed", "low", "Application data backup allowed",
            "android:allowBackup=\"true\" lets `adb backup` extract app data from a device.",
        ))
    if app.get(_ANDROID_NS + "usesCleartextTraffic") == "true":
        findings.append(_finding(
            "cleartext_traffic", "medium", "Cleartext HTTP traffic permitted",
            "android:usesCleartextTraffic=\"true\" allows unencrypted HTTP, enabling MITM.",
        ))

    for tag in ("activity", "service", "receiver", "provider"):
        for comp in app.findall(tag):
            name = comp.get(_ANDROID_NS + "name", "?")
            exported = comp.get(_ANDROID_NS + "exported")
            permission = comp.get(_ANDROID_NS + "permission")
            if exported == "true" and not permission:
                findings.append(_finding(
                    "exported_component", "medium", f"Exported {tag} without permission: {name}",
                    f"{tag} '{name}' is exported (android:exported=\"true\") with no permission guard, "
                    "so any app on the device can invoke it.",
                ))
    return findings


def analyze_sources(text: str, source: str = "decompiled") -> list[dict]:
    """Scan decompiled source text for hardcoded secrets and record endpoints."""
    findings = scan_secrets(text, source=source)
    hosts = {m.group(0) for m in _URL_RE.finditer(text or "")}
    for url in sorted(hosts)[:50]:
        findings.append({
            "type": "finding", "severity": "info", "category": "mobile_endpoint",
            "title": f"Endpoint referenced in app: {url}", "host": url, "matched_at": url,
            "description": "URL hardcoded in the app; candidate for follow-on API testing.",
        })
    return findings


class MobileAnalyzer:
    """Runs apktool + jadx on an APK, then the pure analyzers over the output."""

    tools_required = ["apktool", "jadx"]

    async def analyze_apk(self, apk_path: str) -> list[dict]:
        apk = Path(apk_path)
        if not apk.exists():
            logger.error("APK not found: %s", apk_path)
            return []

        findings: list[dict] = []
        with tempfile.TemporaryDirectory(prefix="zs-mobile-") as tmp:
            out = Path(tmp) / "decoded"
            res = await run_tool(["apktool", "d", "-f", "-o", str(out), str(apk)], timeout=300)
            manifest = out / "AndroidManifest.xml"
            if manifest.exists():
                findings.extend(analyze_manifest(manifest.read_text(errors="ignore")))
            else:
                logger.warning("apktool produced no manifest (rc=%s)", res.returncode)

            # Decompile to Java and scan the concatenated sources for secrets/endpoints.
            jadx_out = Path(tmp) / "jadx"
            await run_tool(["jadx", "-d", str(jadx_out), str(apk)], timeout=600)
            for java in list(jadx_out.rglob("*.java"))[:2000]:
                try:
                    findings.extend(analyze_sources(java.read_text(errors="ignore"), source=java.name))
                except Exception as e:
                    logger.debug("read failed %s: %s", java, e)
        logger.info("Mobile analysis of %s: %d findings", apk.name, len(findings))
        return findings
