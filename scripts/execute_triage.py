# execute_triage.py

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    dump_path = "/app/data/dumps/ubuntu_mem_phase1.lime"
    
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "src.mcp_server.server"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("=" * 80)
            print("EXECUTING MALWARE TRIAGE WORKFLOW")
            print("=" * 80)
            
            # Step 1: Smart Triage
            print("\n[1/6] Running smart_triage...")
            triage_result = await session.call_tool("smart_triage", {
                "dump_path": dump_path
            })
            print(f"✅ {triage_result.content[0].text[:200]}")
            
            # Step 2: Batch Plugins
            print("\n[2/6] Running batch_plugins...")
            plugins_result = await session.call_tool("batch_plugins", {
                "dump_path": dump_path,
                "goal": "malware_detection"
            })
            print(f"✅ {plugins_result.content[0].text[:200]}")
            
            # Step 3: Extract IOCs
            print("\n[3/6] Extracting IOCs...")
            iocs_result = await session.call_tool("extract_iocs", {
                "dump_path": dump_path
            })
            print(f"✅ {iocs_result.content[0].text[:200]}")
            
            # Step 4: Validate IOCs
            print("\n[4/6] Validating IOCs...")
            validate_result = await session.call_tool("validate_iocs", {
                "dump_path": dump_path
            })
            print(f"✅ {validate_result.content[0].text[:200]}")
            
            # Step 5: Map MITRE
            print("\n[5/6] Mapping to MITRE ATT&CK...")
            mitre_result = await session.call_tool("map_mitre", {
                "dump_path": dump_path
            })
            print(f"✅ {mitre_result.content[0].text[:200]}")
            
            # Step 6: Generate Report
            print("\n[6/6] Generating report...")
            report_result = await session.call_tool("generate_report", {
                "dump_path": dump_path
            })
            print(f"✅ {report_result.content[0].text[:500]}")
            
            print("\n" + "=" * 80)
            print("WORKFLOW COMPLETE")
            print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
