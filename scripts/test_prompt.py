# test_prompt.py

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
            
            # Get malware_triage_prompt
            prompt_result = await session.get_prompt(
                "malware_triage_prompt",
                arguments={
                    "dump_path": "/app/data/dumps/mem_phase1.raw"
                }
            )
            
            print("=" * 80)
            print("MALWARE TRIAGE PROMPT")
            print("=" * 80)
            print(prompt_result.description)
            print("\n" + "-" * 80)
            
            for message in prompt_result.messages:
                print(f"\n[{message.role.upper()}]")
                print(message.content.text)
            
            print("\n" + "=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
