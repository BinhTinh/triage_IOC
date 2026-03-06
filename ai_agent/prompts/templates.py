PLANNING_PROMPT = """You are a memory forensics expert. Analyze the following context and plan the investigation.

**Context:**
- OS Type: {os_type}
- OS Version: {os_version}
- Analysis Goal: {goal}
- Available Plugins: {plugins}

**Suggested Plan:**
{suggested_plugins}

**Your Task:**
1. Review the suggested plugins
2. Determine if the list is sufficient
3. Add or remove plugins if needed
4. Explain your reasoning

**Response Format (JSON):**
{{
    "approved": true/false,
    "modifications": [],
    "reasoning": "...",
    "priority_order": []
}}
"""

ANALYSIS_PROMPT = """You are an IOC extraction specialist. Analyze the plugin results to identify indicators of compromise.

**Plugin Results Summary:**
{results_summary}

**Total Findings:** {total_findings}

**Your Task:**
1. Review all findings for suspicious patterns
2. Identify additional IOCs not caught by automated extraction
3. Assess confidence levels
4. Suggest validation priorities

**Response Format (JSON):**
{{
    "additional_iocs": [],
    "false_positives": [],
    "priority_validation": [],
    "insights": ""
}}
"""

VALIDATION_PROMPT = """You are a threat intelligence analyst. Review the IOC validation results.

**Validation Results:**
- Malicious: {malicious_count}
- Suspicious: {suspicious_count}
- Benign: {benign_count}

**MITRE ATT&CK Techniques:**
{techniques}

**Your Task:**
1. Assess overall threat level
2. Identify attack patterns
3. Suggest immediate actions
4. Recommend further investigation areas

**Response Format (JSON):**
{{
    "threat_assessment": "",
    "attack_pattern": "",
    "immediate_actions": [],
    "further_investigation": []
}}
"""