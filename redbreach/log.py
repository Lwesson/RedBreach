import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(data_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure redbreach logging, rotating file + console.

    Args:
        data_dir: Path to ~/.redbreach/ (creates if needed)
        level: Log level string (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path = data_dir / "redbreach.log"

    logger = logging.getLogger("redbreach")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Idempotent: the CLI group AND each subcommand both call setup_logging, so
    # without clearing, every run stacked duplicate handlers -> each log line
    # written twice (or more). Reset before (re)adding.
    for handler in logger.handlers[:]:
        handler.close()
    logger.handlers.clear()

    # Rotating file handler, 10MB max, 5 backups
    file_handler = RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(file_handler)

    # Console handler, WARNING and above only (rich handles normal output)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(
        logging.Formatter("[%(levelname)s] %(message)s")
    )
    logger.addHandler(console_handler)

    return logger
