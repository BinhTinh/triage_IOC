import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv
from ai_agent.clients.mcp_client import MCPClient
from ai_agent.clients.deepseek_client import DeepSeekClient

load_dotenv()

async def main():
    mcp = MCPClient()
    llm = DeepSeekClient(os.getenv("DEEPSEEK_API_KEY"))
    
    try:
        await mcp.initialize()
        
        print(f"✓ MCP Connected: {len(mcp.tools)} tools available")
        print(f"✓ DeepSeek API ready")
        
        dumps = await mcp.call_tool("list_available_dumps")
        print(f"\n✓ Found {dumps['total_files']} dumps")
        
        if dumps['total_files'] == 0:
            print("❌ No dumps found")
            return
        
        dump_file = dumps['files'][0]
        dump_path = dump_file['path']
        
        print(f"\n🔍 Testing workflow with: {dump_file['filename']}")
        
        os_info = await mcp.call_tool("detect_os", dump_path=dump_path)
        print(f"✓ OS: {os_info.get('os_type', 'unknown')} {os_info.get('version', '')}")
        
        response = await llm.chat([
            {"role": "system", "content": "You are a forensics expert."},
            {"role": "user", "content": f"The memory dump is from {os_info['os_type']} {os_info['version']}. What plugins should I run for malware detection? Keep it brief."}
        ])
        
        print(f"\n💬 DeepSeek Response:\n{response.content}")
        
    finally:
        await mcp.close()

if __name__ == "__main__":
    asyncio.run(main())