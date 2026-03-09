from ai_agent.clients.mcp_client import MCPClient
from ai_agent.clients.deepseek_client import DeepSeekClient
from ai_agent.prompts.system_prompts import build_interpretation_prompt


async def intake_node(state: dict, mcp: MCPClient, llm: DeepSeekClient) -> dict:
    print("\n📥 INTAKE")
    dumps = await mcp.call("list_dumps")

    if dumps["total_files"] == 0:
        raise RuntimeError("No dump files found in dumps directory")

    dump_path = dumps["files"][0]["path"]
    os_info = await mcp.call("detect_os", dump_path=dump_path)

    print(f"   ✓ Dump : {dump_path}")
    print(f"   ✓ OS   : {os_info['os_type']} {os_info.get('version', '')} {os_info.get('arch', '')}")

    state["dump_path"] = dump_path
    state["os_info"] = os_info
    return state


async def execution_node(state: dict, mcp: MCPClient, llm: DeepSeekClient) -> dict:
    print("\n⚙️  EXECUTION")
    result = await mcp.call(
        "run_plugins",
        dump_path=state["dump_path"],
        os_type=state["os_info"]["os_type"],
    )

    failed_plugins = [k for k, v in result["results"].items() if not v["success"]]
    print(f"   ✓ Plugins : {result['successful']}/{result['total']} succeeded")
    if failed_plugins:
        print(f"   ⚠️  Failed : {failed_plugins}")

    state["plugin_results"] = result
    return state


async def analysis_node(state: dict, mcp: MCPClient, llm: DeepSeekClient) -> dict:
    print("\n🔍 ANALYSIS")
    result = await mcp.call(
        "ioc_extract",
        plugin_results=state["plugin_results"],
        os_type=state["os_info"]["os_type"],
    )

    s = result["summary"]
    if s["total"] == 0:
        print("   ⚠️  No IOCs extracted")
        state["network_iocs"] = []
        state["host_iocs"] = []
        state["ioc_summary"] = s
        return state

    print(f"   ✓ Total    : {s['total']} IOCs")
    print(f"   ✓ Network  : {s['network_count']}")
    print(f"   ✓ Host     : {s['host_count']}")
    print(f"   📊 high={s['high']}, medium={s['medium']}, low={s['low']}")

    state["network_iocs"] = result["network_iocs"]
    state["host_iocs"] = result["host_iocs"]
    state["ioc_summary"] = s
    return state


async def validation_node(state: dict, mcp: MCPClient, llm: DeepSeekClient) -> dict:
    print("\n✅ VALIDATION")
    network_iocs = state.get("network_iocs", [])
    host_iocs = state.get("host_iocs", [])

    if not network_iocs and not host_iocs:
        print("   ⚠️  No IOCs to validate")
        state["validated"] = {
            "malicious": [], "suspicious": [], "benign": [],
            "summary": {"malicious": 0, "suspicious": 0, "benign": 0,
                        "vt_checked": 0, "deepseek_reasoning": ""},
        }
        return state

    result = await mcp.call(
        "ioc_validate",
        network_iocs=network_iocs,
        host_iocs=host_iocs,
        os_type=state["os_info"]["os_type"],
    )

    s = result["summary"]
    print(f"   ✓ Malicious  : {s['malicious']}")
    print(f"   ✓ Suspicious : {s['suspicious']}")
    print(f"   ✓ Benign     : {s['benign']}")
    print(f"   ✓ VT checked : {s['vt_checked']}")

    state["validated"] = result
    return state


async def interpretation_node(state: dict, mcp: MCPClient, llm: DeepSeekClient) -> dict:
    print("\n🧠 INTERPRETATION")
    validated = state.get("validated", {})
    malicious = validated.get("malicious", [])
    suspicious = validated.get("suspicious", [])

    if not malicious and not suspicious:
        print("   ℹ️  No threats — skipping")
        state["interpretation"] = {}
        return state

    prompt = build_interpretation_prompt(
        malicious=malicious,
        suspicious=suspicious,
        os_info=state["os_info"],
    )

    reasoning, content = await llm.reason(prompt)
    print(f"   ✓ Reasoning : {len(reasoning)} chars")
    print(f"   ✓ Analysis  : {content[:120]}...")

    state["interpretation"] = {"reasoning": reasoning, "analysis": content}
    return state


async def report_node(state: dict, mcp: MCPClient, llm: DeepSeekClient) -> dict:
    print("\n📄 REPORT")
    v = state.get("validated", {}).get("summary", {})
    s = state.get("ioc_summary", {})
    interp = state.get("interpretation", {})

    print(f"   Total IOCs   : {s.get('total', 0)}")
    print(f"   Malicious    : {v.get('malicious', 0)}")
    print(f"   Suspicious   : {v.get('suspicious', 0)}")
    print(f"   Benign       : {v.get('benign', 0)}")

    if interp.get("analysis"):
        print(f"\n   📋 Interpretation:\n   {interp['analysis'][:300]}")

    state["completed"] = True
    return state
