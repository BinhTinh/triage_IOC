# check_server.py

import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "src.mcp_server.server"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            tools_result = await session.list_tools()
            prompts_result = await session.list_prompts()
            
            tools = tools_result.tools
            prompts = prompts_result.prompts
            
            print("=" * 80)
            print(f"📦 TOOLS: {len(tools)}")
            print("=" * 80)
            for tool in sorted(tools, key=lambda x: x.name):
                desc = tool.description[:60] if tool.description else "No description"
                print(f"  • {tool.name:<35} {desc}")
            
            print("\n" + "=" * 80)
            print(f"🎯 PROMPTS: {len(prompts)}")
            print("=" * 80)
            for prompt in sorted(prompts, key=lambda x: x.name):
                desc = prompt.description[:60] if prompt.description else "No description"
                print(f"  • {prompt.name:<35} {desc}")
            
            print("\n" + "=" * 80)
            print(f"TOTAL: {len(tools)} tools + {len(prompts)} prompts = {len(tools) + len(prompts)}")
            print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
