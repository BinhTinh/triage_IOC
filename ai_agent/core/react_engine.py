# ai_agent/core/react_engine.py
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class ReActStep:
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict] = None
    observation: Optional[Any] = None
    reflection: Optional[str] = None

class ReActEngine:
    def __init__(self, llm, mcp):
        self.llm = llm
        self.mcp = mcp
        self.max_iterations = 5
    
    async def run(self, system_prompt: str, user_prompt: str, available_tools: List[str], state: Dict) -> Dict[str, Any]:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        tools_schema = [self._tool_to_openai_format(t) for t in available_tools]
        steps = []
        
        for iteration in range(self.max_iterations):
            try:
                response = await self.llm.chat(messages, tools=tools_schema, temperature=0.3)
            except Exception as e:
                print(f"   ⚠️  LLM error: {e}")
                break
            
            if response.tool_calls:
                for tool_call in response.tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)
                    
                    enriched_args = self._enrich_args(tool_name, tool_args, state)
                    
                    try:
                        observation = await self.mcp.call_tool(tool_name, **enriched_args)
                    except Exception as e:
                        observation = {"error": str(e)}
                        print(f"   ⚠️  Tool error ({tool_name}): {e}")
                    
                    steps.append(ReActStep(
                        thought=response.content or "",
                        action=tool_name,
                        action_input=enriched_args,
                        observation=observation
                    ))
                    
                    messages.append({
                        "role": "assistant",
                        "content": response.content,
                        "tool_calls": [{"id": tool_call.id, "type": "function", "function": {"name": tool_name, "arguments": tool_call.function.arguments}}]
                    })
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(observation, default=str)[:2000]
                    })
            else:
                steps.append(ReActStep(thought=response.content, reflection=response.content))
                break
        
        if not steps:
            return {"steps": [], "updates": {}, "reasoning_log": []}
        
        try:
            final_response = await self.llm.chat(
                messages + [{"role": "user", "content": "Summarize your decisions and return final state updates as JSON with keys matching the state structure."}], 
                temperature=0
            )
            updates = json.loads(final_response.content)
        except:
            updates = {"reasoning": steps[-1].thought if steps else ""}
        
        return {
            "steps": steps,
            "updates": updates,
            "reasoning_log": [s.thought for s in steps if s.thought]
        }
    
    def _enrich_args(self, tool_name: str, tool_args: Dict, state: Dict) -> Dict:
        enriched = dict(tool_args)
        
        if tool_name in ["smart_triage", "detect_os", "win_batch_plugins", "linux_batch_plugins"]:
            if "dump_path" not in enriched and state.get("dump_path"):
                enriched["dump_path"] = state["dump_path"]
        
        if tool_name in ["smart_triage"] and "goal" not in enriched and state.get("goal"):
            enriched["goal"] = state["goal"]
        
        if tool_name in ["ioc_extract"]:
            if "plugin_results" not in enriched and state.get("plugin_results"):
                enriched["plugin_results"] = state["plugin_results"]
            if "os_type" not in enriched and state.get("os_info"):
                enriched["os_type"] = state["os_info"]["os_type"]
        
        if tool_name in ["ioc_validate"]:
            if "iocs" not in enriched and state.get("iocs"):
                enriched["iocs"] = state["iocs"]
            if "os_type" not in enriched and state.get("os_info"):
                enriched["os_type"] = state["os_info"]["os_type"]
        
        if tool_name in ["ioc_map_mitre"] and "validated_iocs" not in enriched and state.get("validated_iocs"):
            enriched["validated_iocs"] = state["validated_iocs"]
        
        if tool_name in ["ioc_generate_report"]:
            if "case_id" not in enriched and state.get("case_id"):
                enriched["case_id"] = state["case_id"]
            if "validated_iocs" not in enriched and state.get("validated_iocs"):
                enriched["validated_iocs"] = state["validated_iocs"]
            if "mitre_mapping" not in enriched and state.get("mitre_mapping"):
                enriched["mitre_mapping"] = state["mitre_mapping"]
            if "format" not in enriched:
                enriched["format"] = "both"
            if "plugin_results" not in enriched and state.get("plugin_results"):
                enriched["plugin_results"] = state["plugin_results"]
        
        return enriched
    
    def _tool_to_openai_format(self, tool_name: str) -> Dict:
        tool_desc = self.mcp.get_tool_description(tool_name)
        
        params = self._get_params_schema(tool_name)
        required = self._get_required_params(tool_name)
        
        return {
            "type": "function",
            "function": {
                "name": tool_name,
                "description": tool_desc[:500],
                "parameters": {
                    "type": "object",
                    "properties": params,
                    "required": required
                }
            }
        }
    
    def _get_params_schema(self, tool_name: str) -> Dict:
        params_map = {
            "list_available_dumps": {},
            "detect_os": {
                "dump_path": {"type": "string", "description": "Path to memory dump file"}
            },
            "smart_triage": {
                "dump_path": {"type": "string", "description": "Path to memory dump file"},
                "goal": {"type": "string", "enum": ["malware_detection", "incident_response", "rootkit_hunt", "quick_triage"]}
            },
            "win_batch_plugins": {
                "dump_path": {"type": "string", "description": "Path to Windows memory dump"},
                "plugins": {"type": "array", "items": {"type": "string"}, "description": "List of plugin names"},
                "max_concurrent": {"type": "integer", "default": 3}
            },
            "linux_batch_plugins": {
                "dump_path": {"type": "string", "description": "Path to Linux memory dump"},
                "plugins": {"type": "array", "items": {"type": "string"}, "description": "List of plugin names"},
                "max_concurrent": {"type": "integer", "default": 3}
            },
            "win_compare_processes": {
                "dump_path": {"type": "string", "description": "Path to Windows memory dump"}
            },
            "linux_compare_processes": {
                "dump_path": {"type": "string", "description": "Path to Linux memory dump"}
            },
            "ioc_extract": {
                "plugin_results": {"type": "object", "description": "Results from batch_plugins"},
                "os_type": {"type": "string", "enum": ["windows", "linux"]}
            },
            "ioc_validate": {
                "iocs": {"type": "array", "description": "List of IOC objects"},
                "os_type": {"type": "string", "enum": ["windows", "linux"]}
            },
            "ioc_map_mitre": {
                "validated_iocs": {"type": "object", "description": "Results from ioc_validate"}
            },
            "ioc_generate_report": {
                "case_id": {"type": "string", "description": "Case ID"},
                "validated_iocs": {"type": "object", "description": "Validated IOCs"},
                "mitre_mapping": {"type": "object", "description": "MITRE mapping"},
                "plugin_results": {"type": "object", "description": "Raw plugin outputs for evidence"},
                "format": {"type": "string", "enum": ["json", "markdown", "both"], "default": "both"}
            }
        }
        return params_map.get(tool_name, {})
    
    def _get_required_params(self, tool_name: str) -> List[str]:
        required_map = {
            "list_available_dumps": [],
            "detect_os": [],
            "smart_triage": [],
            "win_batch_plugins": ["plugins"],
            "linux_batch_plugins": ["plugins"],
            "win_compare_processes": [],
            "linux_compare_processes": [],
            "ioc_extract": ["plugin_results"],
            "ioc_validate": ["iocs"],
            "ioc_map_mitre": ["validated_iocs"],
            "ioc_generate_report": ["validated_iocs", "mitre_mapping"]
        }
        return required_map.get(tool_name, [])
