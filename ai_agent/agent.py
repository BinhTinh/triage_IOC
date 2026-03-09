import asyncio
from ai_agent.clients.mcp_client import MCPClient
from ai_agent.clients.deepseek_client import DeepSeekClient
from ai_agent.graph.nodes import (
    intake_node,
    execution_node,
    analysis_node,
    validation_node,
    interpretation_node,
    report_node,
)
from dotenv import load_dotenv
load_dotenv()


async def main():
    async with MCPClient() as mcp:
        print(f"✓ MCP connected: {mcp.available_tools}")

        llm = DeepSeekClient()
        state = {}

        pipeline = [
            intake_node,
            execution_node,
            analysis_node,
            validation_node,
            interpretation_node,
            report_node,
        ]

        for node in pipeline:
            state = await node(state, mcp, llm)


if __name__ == "__main__":
    asyncio.run(main())
