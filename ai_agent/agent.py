import asyncio
import os
from dotenv import load_dotenv
from ai_agent.clients.mcp_client import MCPClient
from ai_agent.clients.deepseek_client import DeepSeekClient
from ai_agent.graph.workflow import create_workflow
from ai_agent.graph.state import ForensicsState

load_dotenv()

class ForensicsAgent:
    def __init__(self):
        self.mcp = MCPClient()
        self.llm = DeepSeekClient(os.getenv("DEEPSEEK_API_KEY"))
        self.workflow = None
        self._initialized = False
    
    async def initialize(self):
        if self._initialized:
            return
        await self.mcp.initialize()
        self.workflow = create_workflow(self.mcp, self.llm)
        self._initialized = True
        print(f"✓ Agent initialized: {len(self.mcp.tools)} tools")
    
    async def analyze(self, dump_path: str = None, goal: str = "malware_detection"):
        await self.initialize()
        
        initial_state: ForensicsState = {
            "dump_path": dump_path,
            "goal": goal,
            "case_id": None,
            "os_info": None,
            "plugin_list": [],
            "plugin_results": {},
            "iocs": [],
            "validated_iocs": {},
            "mitre_mapping": {},
            "report_path": None,
            "error": None,
            "progress": 0,
            "reasoning_log": [],
            "needs_deeper_scan": False,
            "additional_plugins": []
        }
        
        print(f"\n🚀 Starting ReAct Analysis...")
        print(f"   Goal: {goal}")
        
        result = await self.workflow.ainvoke(initial_state)
        
        if result.get("error"):
            print(f"\n❌ Error: {result['error']}")
            return result
        
        print(f"\n✅ Analysis complete!")
        print(f"   Case: {result.get('case_id')}")
        print(f"   IOCs: {len(result.get('iocs', []))}")
        malicious = result.get("validated_iocs", {}).get("summary", {}).get("malicious", 0)
        print(f"   Malicious: {malicious}")
        print(f"\n📊 LLM Stats: {self.llm.get_stats()}")
        
        return result
    
    async def close(self):
        await self.mcp.close()

async def main():
    agent = ForensicsAgent()
    
    try:
        result = await agent.analyze(goal="malware_detection")
    finally:
        await agent.close()

if __name__ == "__main__":
    asyncio.run(main())
