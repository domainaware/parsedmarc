from __future__ import annotations

import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def configure_logging(log_level: int, log_file: str | None = None) -> None:
    """Configure the parsedmarc logger's handlers.

    This is needed for child processes (e.g. parallel report parsing
    workers) to properly log messages, since a spawned/forkserver process
    does not inherit the parent's configured logging handlers.

    Args:
        log_level: The logging level (e.g., logging.DEBUG, logging.WARNING)
        log_file: Optional path to log file
    """
    # Set the log level
    logger.setLevel(log_level)

    # Add StreamHandler with formatter if not already present
    # Check if we already have a StreamHandler to avoid duplicates
    # Use exact type check to distinguish from FileHandler subclass
    has_stream_handler = any(type(h) is logging.StreamHandler for h in logger.handlers)

    if not has_stream_handler:
        formatter = logging.Formatter(
            fmt="%(levelname)8s:%(filename)s:%(lineno)d:%(message)s",
            datefmt="%Y-%m-%d:%H:%M:%S",
        )
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Add FileHandler if log_file is specified
    if log_file:
        try:
            fh = logging.FileHandler(log_file, "a")
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except (IOError, OSError, PermissionError) as error:
            logger.warning(f"Unable to write to log file: {error}")
