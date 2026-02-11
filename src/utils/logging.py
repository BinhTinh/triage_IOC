import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.config.settings import settings


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        if hasattr(record, "case_id"):
            log_data["case_id"] = record.case_id
        
        if hasattr(record, "plugin"):
            log_data["plugin"] = record.plugin
        
        return str(log_data)


def setup_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None
) -> logging.Logger:
    level = level or settings.log_level
    
    logger = logging.getLogger("volatility3-ioc")
    logger.setLevel(getattr(logging, level.upper()))
    
    if logger.handlers:
        return logger
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "volatility3-ioc") -> logging.Logger:
    return logging.getLogger(name)


logger = setup_logging()