import logging
import sys
import structlog
from pathlib import Path
from src.config import Config

def setup_logging():
    # Base logging level
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    # Path to audit log file
    audit_log_path = Config.BASE_DIR / "cyberguard.audit.log"

    # Define processors for structured logs
    processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure structlog to output both to file (JSON format) and stdout (Console format)
    structlog.configure(
        processors=processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # File Handler (JSON formatter)
    file_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
    )
    file_handler = logging.FileHandler(audit_log_path, encoding="utf-8")
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.INFO)

    # Console Handler (Pretty-print text formatter)
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=True),
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    # Configure root logger handlers
    root_logger = logging.getLogger()
    root_logger.handlers = [file_handler, console_handler]

setup_logging()

def get_logger(name: str):
    return structlog.get_logger(name)
