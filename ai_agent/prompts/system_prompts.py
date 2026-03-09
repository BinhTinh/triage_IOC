import json


def build_interpretation_prompt(malicious: list, suspicious: list, os_info: dict) -> str:
    os_type = os_info.get("os_type", "windows")
    os_ver = os_info.get("version", "unknown")

    ioc_block = json.dumps(
        {"malicious": malicious[:10], "suspicious": suspicious[:20]},
        indent=2
    )

    return f"""You are a malware analyst performing memory forensics on a {os_type} {os_ver} system.

Analyze the following IOCs extracted from a memory dump and provide:
1. Likely malware family or attack type
2. Confidence level (0-100%)
3. Kill chain stages observed (MITRE ATT&CK)
4. Most critical IOCs and why
5. Recommended follow-up actions

IOCs:
{ioc_block}

Be concise and precise. Focus on behavioral patterns across IOCs, not individual indicators.
"""
