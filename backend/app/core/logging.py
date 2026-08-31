import logging
import sys
from typing import Optional


def setup_logging(service: str = "backend", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("sentinel")
    if logger.handlers:
        return logger

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(service)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # bind service name via extra
    logger = logging.LoggerAdapter(logger, {"service": service})
    return logger


def get_logger(service: str = "backend") -> logging.LoggerAdapter:
    logger = logging.getLogger("sentinel")
    if not logger.handlers:
        setup_logging(service=service)
    return logging.LoggerAdapter(logger, {"service": service})
