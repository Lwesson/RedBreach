"""Tests for the Burp Suite XML import parsers (previously untested, wired to CLI)."""
from base64 import b64encode

from redbreach.core.burp_bridge import import_burp_xml, _strip_html


def _write(tmp_path, name, xml):
    p = tmp_path / name
    p.write_text(xml)
    return p


def test_import_issues(tmp_path):
    req = b64encode(b"GET /login HTTP/1.1").decode()
    xml = f"""<issues>
      <issue>
        <name>SQL Injection</name>
        <type>1234</type>
        <severity>High</severity>
        <confidence>Certain</confidence>
        <host ip="1.2.3.4">https://example.com</host>
        <path>/login</path>
        <issueDetail>&lt;b&gt;Detail&lt;/b&gt; here</issueDetail>
        <remediationDetail>Fix it</remediationDetail>
        <requestresponse>
          <request base64="true">{req}</request>
          <response base64="false">HTTP/1.1 200 OK</response>
        </requestresponse>
      </issue>
    </issues>"""
    findings = import_burp_xml(_write(tmp_path, "issues.xml", xml))
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "SQL Injection"
    assert f["severity"] == "high"
    assert f["matched_at"] == "https://example.com/login"   # host + path joined
    assert f["request"] == "GET /login HTTP/1.1"             # base64 decoded
    assert f["response"] == "HTTP/1.1 200 OK"                # non-b64 passthrough
    assert "<b>" not in f["description"] and "Detail" in f["description"]  # HTML stripped


def test_import_issues_severity_certain_maps_high(tmp_path):
    xml = """<issues><issue><name>X</name><severity>certain</severity>
             <host>https://x</host><path>/</path></issue></issues>"""
    findings = import_burp_xml(_write(tmp_path, "s.xml", xml))
    assert findings[0]["severity"] == "high"


def test_import_items_history(tmp_path):
    resp = b64encode(b"HTTP/1.1 200 OK\r\n\r\n{}").decode()
    xml = f"""<items>
      <item>
        <url>https://example.com/api</url>
        <host ip="1.2.3.4">example.com</host>
        <port>443</port>
        <protocol>https</protocol>
        <method>POST</method>
        <status>200</status>
        <mimetype>JSON</mimetype>
        <responselength>1234</responselength>
        <response base64="true">{resp}</response>
      </item>
    </items>"""
    items = import_burp_xml(_write(tmp_path, "items.xml", xml))
    assert len(items) == 1
    it = items[0]
    assert it["type"] == "http_history"
    assert it["url"] == "https://example.com/api"
    assert it["method"] == "POST"
    assert it["status_code"] == 200          # coerced to int
    assert it["port"] == 443
    assert "200 OK" in it["response_snippet"]  # base64 decoded


def test_import_unknown_root_returns_empty(tmp_path):
    assert import_burp_xml(_write(tmp_path, "u.xml", "<other><x/></other>")) == []


def test_import_malformed_xml_returns_empty(tmp_path):
    assert import_burp_xml(_write(tmp_path, "bad.xml", "<issues><issue>")) == []


def test_status_non_numeric_is_none(tmp_path):
    xml = "<items><item><url>x</url><status>timeout</status></item></items>"
    assert import_burp_xml(_write(tmp_path, "st.xml", xml))[0]["status_code"] is None


def test_strip_html():
    assert _strip_html("<p>hi <b>there</b></p>") == "hi there"
    assert _strip_html("a &lt;tag&gt; &amp; b") == "a <tag> & b"
