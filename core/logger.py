from loguru import logger
from rich.console import Console
from rich.text import Text

# Shared with rich.progress bars (see core/engine.py) so log lines print
# cleanly above an active progress bar instead of corrupting its render.
console = Console()

def setup_logger(verbose: bool = False):
    level = "DEBUG" if verbose else "INFO"
    logger.remove()
    logger.add(
        lambda msg: console.print(Text.from_ansi(msg.rstrip("\n"))),
        enqueue=True,
        colorize=True,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> - <level>{message}</level>",
        level=level,
    )
    return logger
