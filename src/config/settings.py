import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class Settings:
    vt_api_key: Optional[str] = field(default_factory=lambda: os.getenv("VT_API_KEY"))
    abuseipdb_key: Optional[str] = field(default_factory=lambda: os.getenv("ABUSEIPDB_KEY"))
    deepseek_api_key: str = field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    deepseek_model: str = field(default_factory=lambda: os.getenv("DEEPSEEK_MODEL", "deepseek-chat"))
    use_deepseek: bool = field(default_factory=lambda: os.getenv("USE_DEEPSEEK", "true").lower() == "true")
    use_local_patterns: bool = field(default_factory=lambda: os.getenv("USE_LOCAL_PATTERNS", "true").lower() == "true")
    
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_URL"))
    database_url: Optional[str] = field(default_factory=lambda: os.getenv("DATABASE_URL"))
    
    mcp_host: str = field(default_factory=lambda: os.getenv("MCP_HOST", "0.0.0.0"))
    mcp_port: int = field(default_factory=lambda: int(os.getenv("MCP_PORT", "8000")))
    mcp_transport: str = field(default_factory=lambda: os.getenv("MCP_TRANSPORT", "stdio"))
    
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    
    base_dir: str = field(default_factory=lambda: os.getenv("BASE_DIR", str(Path(__file__).parent.parent.parent)))
    config_dir: str = field(default_factory=lambda: os.getenv("CONFIG_DIR", str(Path(__file__).parent.parent.parent / "config")))
    data_dir: str = field(default_factory=lambda: os.getenv("DATA_DIR", str(Path(__file__).parent.parent.parent / "data")))
    dumps_dir: str = field(default_factory=lambda: os.getenv("DUMPS_DIR", str(Path(__file__).parent.parent.parent / "data" / "dumps")))
    symbols_dir: str = field(default_factory=lambda: os.getenv("SYMBOLS_DIR", str(Path(__file__).parent.parent.parent / "data" / "symbols")))
    reports_dir: str = field(default_factory=lambda: os.getenv("REPORTS_DIR", str(Path(__file__).parent.parent.parent / "data" / "reports")))
    cache_dir: str = field(default_factory=lambda: os.getenv("CACHE_DIR", str(Path(__file__).parent.parent.parent / "data" / "cache")))
    volatility_cache_dir: str = field(default_factory=lambda: os.getenv("VOLATILITY_CACHE_DIR", str(Path(__file__).parent.parent.parent / "data" / "cache" / "volatility3")))
    
    volatility_path: str = field(default_factory=lambda: os.getenv("VOLATILITY_PATH", "python3 -m volatility3.cli"))
    
    max_dump_size: int = field(default_factory=lambda: int(os.getenv("MAX_DUMP_SIZE", str(64 * 1024 * 1024 * 1024))))
    plugin_timeout: int = field(default_factory=lambda: int(os.getenv("PLUGIN_TIMEOUT", "600")))
    max_concurrent_plugins: int = field(default_factory=lambda: int(os.getenv("MAX_CONCURRENT_PLUGINS", "3")))
    cache_ttl: int = field(default_factory=lambda: int(os.getenv("CACHE_TTL", "86400")))
    threat_intel_cache_ttl: int = field(default_factory=lambda: int(os.getenv("THREAT_INTEL_CACHE_TTL", "21600")))
    
    allowed_dump_dirs: List[str] = field(default_factory=lambda: [
        d.strip() for d in os.getenv("ALLOWED_DUMP_DIRS", "/app/data/dumps,/data/dumps,./data/dumps").split(",")
    ])
    
    rate_limit_enabled: bool = field(default_factory=lambda: os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true")
    rate_limit_requests: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_REQUESTS", "60")))
    rate_limit_period: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PERIOD", "60")))
    
    def __post_init__(self):
        for dir_attr in ["data_dir", "dumps_dir", "symbols_dir", "reports_dir", "cache_dir", "volatility_cache_dir"]:
            dir_path = Path(getattr(self, dir_attr))
            dir_path.mkdir(parents=True, exist_ok=True)

    use_deepseek_validation: bool = False
    deepseek_api_key: Optional[str] = None


settings = Settings()