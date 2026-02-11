from src.mcp_server.tools.triage import register_triage_tools
from src.mcp_server.tools.windows import register_windows_tools
from src.mcp_server.tools.linux import register_linux_tools
from src.mcp_server.tools.validation import register_validation_tools

__all__ = [
    "register_triage_tools",
    "register_windows_tools",
    "register_linux_tools",
    "register_validation_tools"
]