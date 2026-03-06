from langgraph.graph import StateGraph, END
from ai_agent.graph.state import ForensicsState
from ai_agent.graph.nodes import (
    intake_node, planning_node, execution_node,
    analysis_node, validation_node, interpretation_node, report_node
)


def create_workflow(mcp, llm):
    workflow = StateGraph(ForensicsState)

    async def intake_wrapper(s):
        return await intake_node(s, mcp, llm)

    async def planning_wrapper(s):
        return await planning_node(s, mcp, llm)

    async def execution_wrapper(s):
        return await execution_node(s, mcp, llm)

    async def deeper_scan_wrapper(s):
        deeper_state = {**s, "plugin_list": s.get("additional_plugins", [])}
        result = await execution_node(deeper_state, mcp, llm)
        merged_data = {
            **s.get("plugin_results", {}).get("data", {}),
            **result.get("plugin_results", {}).get("data", {}),
        }
        merged_results = {**s.get("plugin_results", {}), "data": merged_data}
        return {**s, "plugin_results": merged_results}

    async def analysis_wrapper(s):
        return await analysis_node(s, mcp, llm)

    async def validation_wrapper(s):
        return await validation_node(s, mcp, llm)

    async def interpretation_wrapper(s):
        return await interpretation_node(s, mcp, llm)

    async def report_wrapper(s):
        return await report_node(s, mcp, llm)

    workflow.add_node("intake",          intake_wrapper)
    workflow.add_node("planning",        planning_wrapper)
    workflow.add_node("execution",       execution_wrapper)
    workflow.add_node("deeper_scan",     deeper_scan_wrapper)
    workflow.add_node("analysis",        analysis_wrapper)
    workflow.add_node("validation",      validation_wrapper)
    workflow.add_node("interpretation",  interpretation_wrapper)  
    workflow.add_node("report",          report_wrapper)

    workflow.set_entry_point("intake")

    workflow.add_conditional_edges(
        "intake",
        lambda s: "error" if s.get("error") else "planning",
        {"error": END, "planning": "planning"},
    )

    workflow.add_edge("planning", "execution")

    workflow.add_conditional_edges(
        "execution",
        lambda s: "deeper_scan" if s.get("needs_deeper_scan") else "analysis",
        {"deeper_scan": "deeper_scan", "analysis": "analysis"},
    )

    workflow.add_edge("deeper_scan",    "analysis")
    workflow.add_edge("analysis",       "validation")
    workflow.add_edge("validation",     "interpretation")
    workflow.add_edge("interpretation", "report")
    workflow.add_edge("report",         END)

    return workflow.compile()
