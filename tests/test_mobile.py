from redbreach.modules.mobile import analyze_manifest, analyze_sources

_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'

INSECURE = f'''<manifest {_NS} package="com.x">
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".Exported" android:exported="true"/>
    <service android:name=".Guarded" android:exported="true" android:permission="com.x.PERM"/>
  </application>
</manifest>'''

CLEAN = f'''<manifest {_NS} package="com.x">
  <application android:debuggable="false" android:allowBackup="false">
    <activity android:name=".Main" android:exported="false"/>
  </application>
</manifest>'''


def _cats(findings):
    return {f["category"] for f in findings}


def test_manifest_flags_all_misconfigs():
    cats = _cats(analyze_manifest(INSECURE))
    assert "debuggable" in cats
    assert "backup_allowed" in cats
    assert "cleartext_traffic" in cats
    assert "exported_component" in cats


def test_manifest_guarded_component_not_flagged():
    # The service is exported but permission-guarded → only the activity is flagged.
    exported = [f for f in analyze_manifest(INSECURE) if f["category"] == "exported_component"]
    assert len(exported) == 1
    assert "Exported" in exported[0]["title"]
    assert "Guarded" not in exported[0]["title"]


def test_clean_manifest_no_findings():
    assert analyze_manifest(CLEAN) == []


def test_malformed_manifest_does_not_crash():
    assert analyze_manifest("<manifest not closed") == []


def test_analyze_sources_finds_secret_and_endpoint():
    text = 'String key = "AKIAIOSFODNN7EXAMPLE"; String api = "https://api.example.com/v1";'
    findings = analyze_sources(text, source="Api.java")
    cats = _cats(findings)
    assert "hardcoded_secret" in cats
    assert "mobile_endpoint" in cats
    endpoint = [f for f in findings if f["category"] == "mobile_endpoint"][0]
    assert "api.example.com" in endpoint["host"]
