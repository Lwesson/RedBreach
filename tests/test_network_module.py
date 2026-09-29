import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from redbreach.modules.network import NetworkModule
from redbreach.core.subprocess_runner import SubprocessResult


@pytest.fixture
def module():
    return NetworkModule()


def make_result(stdout="", stderr="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
        timed_out=False, duration_seconds=5.0, command=["test"],
    )


def test_module_name(module):
    assert module.name == "network"


def test_tools_required(module):
    assert "nmap" in module.tools_required


@pytest.mark.asyncio
async def test_recon_nmap_discovery(module):
    mock_result = SubprocessResult(
        stdout="192.168.1.1\n192.168.1.10\n192.168.1.254\n",
        stderr="", returncode=0, timed_out=False, duration_seconds=10.0, command=["nmap"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        assets = await module.recon({"target": "192.168.1.0/24", "type": "pentest"}, [])
    assert len(assets) == 3
    assert all(a["type"] == "host" for a in assets)


@pytest.mark.asyncio
async def test_enumerate_masscan(module):
    """enumerate() runs masscan and returns hosts with port lists."""
    masscan_json = json.dumps([
        {"ip": "192.168.1.1", "timestamp": "1711900800", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
        {"ip": "192.168.1.1", "timestamp": "1711900801", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
        {"ip": "192.168.1.10", "timestamp": "1711900803", "ports": [{"port": 3306, "proto": "tcp", "status": "open"}]},
    ])
    mock_result = make_result(stdout=masscan_json)
    assets = [{"type": "host", "value": "192.168.1.1"}, {"type": "host", "value": "192.168.1.10"}]
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        results = await module.enumerate(
            {"target": "192.168.1.0/24", "type": "pentest", "speed": "normal"}, assets
        )
    host_1 = [r for r in results if r.get("value") == "192.168.1.1"]
    assert len(host_1) == 1
    assert 22 in host_1[0]["ports"]
    assert 80 in host_1[0]["ports"]


@pytest.mark.asyncio
async def test_enumerate_masscan_not_installed(module):
    """enumerate() handles missing masscan gracefully."""
    mock_result = make_result(stdout="", stderr="Command not found: masscan", returncode=127)
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        results = await module.enumerate(
            {"target": "192.168.1.0/24", "type": "pentest"}, [{"type": "host", "value": "192.168.1.1"}]
        )
    assert len(results) == 1


@pytest.mark.asyncio
async def test_scan_nmap_services(module):
    nmap_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>"""
    mock_result = make_result(stdout=nmap_xml)
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        findings = await module.scan({"target": "192.168.1.1", "type": "pentest"},
                                      [{"type": "host", "value": "192.168.1.1"}])
    assert len(findings) == 3
    assert all(f["type"] == "finding" for f in findings)


@pytest.mark.asyncio
async def test_scan_uses_masscan_ports(module):
    """scan() targets only ports discovered by masscan enumerate."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>"""
    mock_result = make_result(stdout=nmap_xml)
    assets = [{"type": "host", "value": "10.0.0.1", "ports": [8080, 8443]}]

    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result) as mock_run:
        findings = await module.scan({"target": "10.0.0.1", "type": "pentest"}, assets)

    cmd = mock_run.call_args[0][0]
    assert "-p" in cmd
    port_idx = cmd.index("-p")
    assert "8080,8443" in cmd[port_idx + 1]


@pytest.mark.asyncio
async def test_scan_nmap_nse_scripts(module):
    """scan() captures NSE script output and elevates severity."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    mock_result = make_result(stdout=nmap_xml)
    assets = [{"type": "host", "value": "192.168.1.1", "ports": [21]}]

    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        findings = await module.scan({"target": "192.168.1.1", "type": "pentest"}, assets)

    assert len(findings) == 1
    assert findings[0]["service"] == "ftp"
    assert findings[0]["nse_scripts"]["ftp-anon"] == "Anonymous FTP login allowed"
    assert findings[0]["severity"] == "medium"  # elevated from "info" due to anonymous


@pytest.mark.asyncio
async def test_suggest_tests_context_aware(module):
    """suggest_tests generates suggestions based on actual scan findings."""
    findings = [
        {"type": "finding", "title": "Open port 21/tcp (ftp)", "severity": "info",
         "category": "network_service", "service": "ftp",
         "nse_scripts": {"ftp-anon": "Anonymous FTP login allowed"},
         "host": "192.168.1.1", "port": "21"},
        {"type": "finding", "title": "Open port 22/tcp (ssh)", "severity": "info",
         "category": "network_service", "service": "ssh",
         "host": "192.168.1.1", "port": "22"},
    ]
    suggestions = await module.suggest_tests({"target": "192.168.1.0/24"}, findings)
    assert len(suggestions) > 0
    descriptions = " ".join(s["description"] for s in suggestions)
    assert "anonymous" in descriptions.lower() or "ftp" in descriptions.lower()


def test_parse_nmap_hosts(module):
    parsed = module.parse_output("nmap_hosts", "10.0.0.1\n10.0.0.2\n")
    assert len(parsed) == 2


def test_parse_nmap_xml(module):
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>"""
    parsed = module.parse_output("nmap_xml", xml)
    assert len(parsed) == 1
    assert parsed[0]["port"] == "80"


@pytest.mark.asyncio
async def test_masscan_uses_real_port_flag_not_top_ports(module):
    # Regression: masscan has no --top-ports (nmap flag); stealth/normal were broken.
    captured = {}

    async def mock_run(cmd, **kwargs):
        if cmd and cmd[0] == "masscan":
            captured["cmd"] = cmd
        return make_result(stdout="[]")

    assets = [{"type": "host", "value": "192.168.1.1"}]
    with patch.object(module, "run_tool", side_effect=mock_run):
        await module.enumerate({"target": "x", "type": "pentest", "speed": "normal"}, assets)
    assert "--top-ports" not in captured["cmd"]
    assert any(a.startswith("-p") for a in captured["cmd"])
