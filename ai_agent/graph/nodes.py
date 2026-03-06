from typing import Any, Dict, List
import json
import re

from ai_agent.core.react_engine import ReActEngine
from ai_agent.prompts.system_prompts import INTAKE_SYSTEM, PLANNING_SYSTEM
from ai_agent.graph.state import ForensicsState


async def intake_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n📥 INTAKE [ReAct]")
    engine = ReActEngine(llm, mcp)

    dump_info = (
        f"dump_path={state.get('dump_path')}"
        if state.get("dump_path")
        else "no dump selected yet"
    )

    user_prompt = f"""
Task: Prepare forensic analysis session.
Current state: {dump_info} | Goal: {state['goal']}

Steps (execute in order):
1. Call list_available_dumps
2. Select: total_files==1 → use it; >1 → most recently modified; 0 → stop
3. Call detect_os(dump_path=<selected path>)

Do NOT ask user for paths.
"""

    result = await engine.run(
        system_prompt=INTAKE_SYSTEM,
        user_prompt=user_prompt,
        available_tools=["list_available_dumps", "detect_os"],
        state=state,
    )

    for step in result["steps"]:
        if step.action == "list_available_dumps" and not state.get("dump_path"):
            files = step.observation.get("files", [])
            if files:
                files_sorted = sorted(files, key=lambda x: x.get("modified_at", ""), reverse=True)
                state["dump_path"] = files_sorted[0]["path"]

    for step in result["steps"]:
        if step.action == "detect_os" and not step.observation.get("error"):
            state["os_info"] = step.observation

    if not state.get("os_info"):
        state["error"] = "Failed to detect OS"
        print("   ❌ OS detection failed")
        return state

    state["reasoning_log"] = result.get("reasoning_log", [])
    state["progress"] = 10
    print(f"   ✓ Dump : {state['dump_path']}")
    print(f"   ✓ OS   : {state['os_info'].get('os_type')} {state['os_info'].get('version', '')}")
    return state


async def planning_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n📋 PLANNING [Direct MCP + LLM Review]")

    os_type = state["os_info"]["os_type"]

    try:
        triage = await mcp.call_tool(
            "smart_triage",
            dump_path=state["dump_path"],
            os_type=os_type,
            goal=state["goal"],
        )
        state["case_id"]     = triage.get("case_id")
        state["plugin_list"] = triage.get("plan", {}).get("plugins", [])
    except Exception as e:
        print(f"   ❌ smart_triage error: {e}")
        state["error"] = str(e)
        return state

    plugin_names = [p["name"] if isinstance(p, dict) else p for p in state["plugin_list"]]

    review_prompt = f"""You are a forensic analysis planner reviewing a plugin execution plan.

Case context:
  OS      : {os_type} {state['os_info'].get('version', '')} {state['os_info'].get('arch', '')}
  Goal    : {state['goal']}
  Dump    : {state['dump_path']}
  Case ID : {state['case_id']}

Plugin plan proposed by smart_triage ({len(plugin_names)} plugins):
{chr(10).join(f"  - {n}" for n in plugin_names)}

Your tasks:
1. Verify the plan covers the goal adequately
2. For Windows + malware_detection or incident_response: confirm these registry plugins are present:
   - windows.registry.hivelist.HiveList
   - windows.registry.printkey.PrintKey
   - windows.registry.userassist.UserAssist
3. For rootkit_hunt: confirm ssdt, callbacks, driverscan are present
4. For network_forensics: confirm handles is present
5. Identify any critical gaps for the goal

Respond in JSON:
{{
  "approved": true,
  "missing_plugins": ["plugin.name.ClassName"],
  "coverage_notes": "brief assessment of plan coverage",
  "estimated_threat_vectors": ["process injection", "persistence", "C2", ...]
}}"""

    try:
        response = await llm.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior forensic analyst reviewing memory analysis plans. "
                        "Respond ONLY with valid JSON. Be concise and precise."
                    ),
                },
                {"role": "user", "content": review_prompt},
            ],
            temperature=0.1,
            max_tokens=1024,
        )

        content = response.content or ""
        import json, re
        json_match = re.search(r'\{[\s\S]+\}', content)
        if json_match:
            review = json.loads(json_match.group())
            state["plan_review"] = review

            print(f"   ✓ LLM review: {'approved' if review.get('approved') else 'needs update'}")
            if review.get("coverage_notes"):
                print(f"   📝 Coverage : {review['coverage_notes'][:80]}")

            missing = review.get("missing_plugins", [])
            if missing:
                print(f"   ⚠️  Missing plugins: {missing}")
                for plugin_name in missing:
                    entry = {"name": plugin_name, "args": {}}
                    if plugin_name not in plugin_names:
                        state["plugin_list"].append(entry)
                print(f"   ✓ Updated  : {len(state['plugin_list'])} plugins total")

            vectors = review.get("estimated_threat_vectors", [])
            if vectors:
                print(f"   🎯 Threat vectors: {', '.join(vectors[:5])}")

    except Exception as e:
        print(f"   ⚠️  LLM review skipped (non-fatal): {e}")
        state["plan_review"] = {}

    state["progress"] = 20
    state["reasoning_log"].append(
        f"Plan: {len(state['plugin_list'])} plugins | "
        f"review: {state.get('plan_review', {}).get('approved', 'skipped')}"
    )
    print(f"   ✓ Case   : {state['case_id']}")
    print(f"   ✓ Plugins: {len(state['plugin_list'])}")
    return state


async def execution_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n⚙️  EXECUTION [Direct MCP]")
    os_type = state["os_info"]["os_type"]

    try:
        result = await mcp.call_tool(
            "batch_plugins",
            dump_path=state["dump_path"],
            plugins=state["plugin_list"],
            max_concurrent=3,
        )
        state["plugin_results"] = result

        success   = result.get("successful", 0)
        total     = result.get("total", 0)
        data_keys = len(result.get("data", {}))
        print(f"   ✓ Executed : {success}/{total} plugins")
        print(f"   ✓ Data keys: {data_keys} plugins with results")

        malfind_key = (
            "windows.malware.malfind.Malfind"
            if os_type == "windows"
            else "linux.malware.malfind.Malfind"
        )
        malfind_rows = result.get("data", {}).get(malfind_key, [])
        needs_deeper = len(malfind_rows) > 3

        hidden_result: Dict[str, Any] = {}
        try:
            hidden_result = await mcp.call_tool(
                "compare_processes",
                dump_path=state["dump_path"],
                os_type=os_type,
            )
            if hidden_result.get("suspicious"):
                print(f"   ⚠️  Hidden processes: {hidden_result.get('hidden_count', 0)}")
                needs_deeper = True
        except Exception as e:
            print(f"   ⚠️  compare_processes skipped: {e}")

        state["needs_deeper_scan"] = needs_deeper
        state["additional_plugins"] = (
            [
                {"name": "windows.ssdt.SSDT",          "args": {}},
                {"name": "windows.callbacks.Callbacks", "args": {}},
            ]
            if needs_deeper and os_type == "windows"
            else (
                [
                    {"name": "linux.malware.check_syscall.Check_syscall", "args": {}},
                    {"name": "linux.malware.check_modules.Check_modules",  "args": {}},
                ]
                if needs_deeper and os_type == "linux"
                else []
            )
        )

    except Exception as e:
        print(f"   ❌ Execution error: {e}")
        state["plugin_results"]    = {"total": 0, "successful": 0, "failed": 0, "results": {}, "data": {}}
        state["needs_deeper_scan"] = False
        state["additional_plugins"] = []

    state["progress"] = 60
    state["reasoning_log"].append(
        f"Executed {state['plugin_results'].get('successful', 0)}"
        f"/{state['plugin_results'].get('total', 0)} plugins"
    )
    print(f"   ✓ Deeper scan needed: {state['needs_deeper_scan']}")
    return state


async def analysis_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n🔍 ANALYSIS [Direct MCP]")
    plugin_data = state.get("plugin_results", {}).get("data", {})

    if not isinstance(plugin_data, dict) or len(plugin_data) == 0:
        print("   ⚠️  No plugin data — skipping IOC extraction")
        state["iocs"] = []
        state["progress"] = 70
        state["reasoning_log"].append("Analysis skipped: no plugin data")
        return state

    print(f"   📊 Plugin data: {len(plugin_data)} plugins with rows")
    for plugin_name, rows in plugin_data.items():
        print(f"      {plugin_name}: {len(rows) if isinstance(rows, list) else '?'} rows")

    try:
        ioc_result = await mcp.call_tool(
            "ioc_extract",
            plugin_results=state["plugin_results"],
            os_type=state["os_info"]["os_type"],
        )
        state["iocs"] = ioc_result.get("iocs", [])
        state["progress"] = 70
        print(f"   ✓ IOCs extracted: {len(state['iocs'])}")

        if state["iocs"]:
            by_type: Dict[str, int] = {}
            for ioc in state["iocs"]:
                ioc_type = ioc.get("ioc_type") or ioc.get("type", "unknown")
                by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            print("   📊 IOC breakdown:")
            for ioc_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"      {ioc_type}: {count}")

    except Exception as e:
        print(f"   ❌ IOC extraction error: {e}")
        state["iocs"] = []
        state["progress"] = 70

    state["reasoning_log"].append(f"Extracted {len(state.get('iocs', []))} IOCs")
    return state


async def validation_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n✅ VALIDATION [Direct MCP]")

    if not state.get("iocs"):
        print("   ⚠️  No IOCs to validate")
        state["validated_iocs"] = {"malicious": [], "suspicious": [], "benign": [], "summary": {"malicious": 0, "suspicious": 0, "benign": 0}}
        state["mitre_mapping"]  = {"total_techniques": 0, "tactics_involved": [], "matrix": {}, "techniques": []}
        state["progress"] = 85
        return state

    print(f"   🔍 Validating {len(state['iocs'])} IOCs...")

    try:
        validated = await mcp.call_tool(
            "ioc_validate",
            iocs=state["iocs"],
            os_type=state["os_info"]["os_type"],
        )
        state["validated_iocs"] = validated

        summary    = validated.get("summary", {})
        malicious  = summary.get("malicious", 0)
        suspicious = summary.get("suspicious", 0)
        benign     = summary.get("benign", 0)

        print(f"   ✓ Validation complete:")
        print(f"      Malicious : {malicious}")
        print(f"      Suspicious: {suspicious}")
        print(f"      Benign    : {benign}")

        if malicious > 0 or suspicious > 0:
            mitre = await mcp.call_tool("ioc_map_mitre", validated_iocs=validated)
            state["mitre_mapping"] = mitre
            print(f"   ✓ MITRE mapping: {mitre.get('total_techniques', 0)} techniques")
        else:
            state["mitre_mapping"] = {"total_techniques": 0, "tactics_involved": [], "matrix": {}, "techniques": {}}

    except Exception as e:
        print(f"   ❌ Validation error: {e}")
        state["validated_iocs"] = {"malicious": [], "suspicious": [], "benign": [], "summary": {"malicious": 0, "suspicious": 0, "benign": 0}}
        state["mitre_mapping"]  = {"total_techniques": 0, "tactics_involved": [], "matrix": {}, "techniques": {}}

    state["progress"] = 85
    state["reasoning_log"].append(f"Validated IOCs: {state['validated_iocs'].get('summary', {})}")
    return state


async def interpretation_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n🧠 INTERPRETATION [DeepSeek Reasoner]")

    validated  = state.get("validated_iocs", {})
    mitre      = state.get("mitre_mapping", {})
    malicious  = validated.get("summary", {}).get("malicious", 0)
    suspicious = validated.get("summary", {}).get("suspicious", 0)

    if malicious == 0 and suspicious == 0:
        print("   ℹ️  No threats — skipping interpretation")
        state["interpretation"] = {"threat_level": "LOW", "analysis": "No threats found", "additional_techniques": []}
        return state

    mal_sample  = validated.get("malicious",  [])[:12]
    susp_sample = validated.get("suspicious", [])[:8]
    techniques  = mitre.get("techniques", [])

    already_mapped = (
        [t.get("id") + " " + t.get("name", "") for t in techniques]
        if isinstance(techniques, list)
        else [k for k in techniques.keys()]
    )

    prompt = f"""You are a senior malware analyst performing memory forensics on a Windows system.

CONFIRMED MALICIOUS IOCs ({malicious} total):
{_format_iocs(mal_sample)}

SUSPICIOUS IOCs ({suspicious} total):
{_format_iocs(susp_sample)}

MITRE techniques already mapped by rule-based engine:
{already_mapped}

Perform deep analysis:
1. Identify malware family: ransomware / RAT / stealer / backdoor / loader / rootkit / worm / cryptominer / banker
2. Find MITRE ATT&CK techniques NOT in the already-mapped list above — analyze IOC context fields carefully
   Consider: T1059.001 PowerShell, T1547.001 Registry Run Keys, T1071.001 Web Protocols,
   T1003 OS Credential Dumping, T1036 Masquerading, T1218 Signed Binary Proxy,
   T1140 Deobfuscate/Decode, T1027 Obfuscated Files, T1083 File Discovery,
   T1082 System Info Discovery, T1016 Network Config Discovery, T1057 Process Discovery
3. Determine kill chain stage: Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Discovery / Lateral Movement / Collection / C2 / Exfiltration / Impact
4. Identify top 3 most critical IOCs and explain why
5. Suggest 1-2 additional Volatility3 plugins that would confirm your hypothesis

Return ONLY valid JSON, no markdown:
{{
  "malware_family": "string",
  "confidence": 0.0,
  "kill_chain_stages": ["string"],
  "additional_techniques": [{{"id": "string", "name": "string", "reason": "string"}}],
  "critical_iocs": [{{"value": "string", "type": "string", "reason": "string"}}],
  "recommended_plugins": [{{"name": "string", "reason": "string"}}],
  "analyst_summary": "string",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW"
}}
IMPORTANT: In your JSON response, use forward slashes (/) for all file paths, 
not backslashes. Example: "C:/Windows/System32/evil.exe" not "C:\\Windows\\..."
"""

    try:
        response = await llm.reason(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=8000,
        )

        content          = response["content"]
        reasoning        = response["reasoning_content"]

        json_match = re.search(r'\{[\s\S]+\}', content)
        if json_match:
            raw_json = json_match.group()
            raw_json = re.sub(
                r'(?<!\\)\\(?!["\\/bfnrtu])',
                r'\\\\',
                raw_json
            )
            try:
                interpretation = json.loads(raw_json)
            except json.JSONDecodeError:
                # Fallback: dùng ast.literal_eval hoặc extract từng field
                import ast
                try:
                    interpretation = ast.literal_eval(raw_json)
                except Exception:
                    interpretation = {"raw": content, "parse_error": "Could not parse JSON"}
                    print(f"   ⚠️  JSON parse failed — storing raw response")

            state["interpretation"] = interpretation
            state["reasoning_content"] = reasoning
            print(f"   ✓ Family    : {interpretation.get('malware_family', 'unknown')}")
            print(f"   ✓ Confidence: {interpretation.get('confidence', 0):.0%}")
            print(f"   ✓ Kill chain: {' → '.join(interpretation.get('kill_chain_stages', []))}")
            print(f"   ✓ Threat    : {interpretation.get('threat_level', 'N/A')}")

            extra = interpretation.get("additional_techniques", [])
            if extra:
                print(f"   ✓ Extra MITRE ({len(extra)} new techniques):")
                for t in extra:
                    print(f"      {t.get('id')} {t.get('name')}: {t.get('reason','')[:70]}")

            critical = interpretation.get("critical_iocs", [])
            if critical:
                print(f"   ✓ Critical IOCs:")
                for c in critical:
                    print(f"      [{c.get('type')}] {c.get('value','')[:60]}: {c.get('reason','')[:60]}")

            recs = interpretation.get("recommended_plugins", [])
            if recs:
                print(f"   ✓ Recommended follow-up plugins:")
                for r in recs:
                    print(f"      {r.get('name')}: {r.get('reason','')[:70]}")

            if reasoning:
                print(f"   📎 CoT reasoning: {len(reasoning)} chars")
        else:
            state["interpretation"] = {"raw": content}
            print(f"   ⚠️  Could not parse JSON from reasoner output")

    except Exception as e:
        print(f"   ⚠️  Interpretation failed (non-fatal): {e}")
        state["interpretation"] = {}

    state["reasoning_log"].append(
        f"LLM interpretation: {state.get('interpretation', {}).get('malware_family', 'N/A')} "
        f"| {state.get('interpretation', {}).get('threat_level', 'N/A')}"
    )
    return state


async def report_node(state: ForensicsState, mcp, llm) -> ForensicsState:
    print("\n📄 REPORT [Direct MCP]")

    malicious  = state.get("validated_iocs", {}).get("summary", {}).get("malicious", 0)
    suspicious = state.get("validated_iocs", {}).get("summary", {}).get("suspicious", 0)
    techniques = state.get("mitre_mapping", {}).get("total_techniques", 0)
    interp     = state.get("interpretation", {})

    print(f"   📊 Final summary:")
    print(f"      Total IOCs : {len(state.get('iocs', []))}")
    print(f"      Malicious  : {malicious}")
    print(f"      Suspicious : {suspicious}")
    print(f"      Techniques : {techniques} (rule) + {len(interp.get('additional_techniques', []))} (LLM)")
    if interp.get("malware_family"):
        print(f"      Family     : {interp['malware_family']} ({interp.get('confidence', 0):.0%})")

    try:
        report = await mcp.call_tool(
            "ioc_generate_report",
            case_id=state["case_id"],
            validated_iocs=state["validated_iocs"],
            mitre_mapping=state["mitre_mapping"],
            plugin_results=state.get("plugin_results", {}),
            format="both",
        )
        state["report_path"] = report.get("report_paths")
        paths = report.get("report_paths", {})
        print(f"   ✓ Report generated:")
        print(f"      SUMMARY : {paths.get('summary_txt', 'N/A')}")
        print(f"      IOCs    : {paths.get('iocs_json', 'N/A')}")

    except Exception as e:
        print(f"   ❌ Report generation error: {e}")
        state["report_path"] = None

    state["progress"] = 100
    state["reasoning_log"].append("Report generation complete")
    return state


def _format_iocs(ioc_list: list) -> str:
    lines = []
    for ioc in ioc_list:
        itype     = ioc.get("type", ioc.get("ioc_type", "?"))
        value     = str(ioc.get("value", ""))[:80].replace("\\", "/")
        conf      = ioc.get("confidence", 0)
        source    = ioc.get("source", "")
        context   = ioc.get("context", {})
        technique = context.get("technique", "") if isinstance(context, dict) else ""
        process   = context.get("process",   "") if isinstance(context, dict) else ""
        lines.append(
            f"  [{itype}] {value} "
            f"(conf={conf:.2f}, src={source}"
            + (f", technique={technique}" if technique else "")
            + (f", process={process}"     if process   else "")
            + ")"
        )
    return "\n".join(lines) if lines else "  (none)"
