import os
import sys


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_RED = "\033[91m"

    _ENABLED = (
        os.getenv("NETRECON_NO_COLOR", "").strip() == ""
        and sys.stdout.isatty()
    )

    @classmethod
    def wrap(cls, text, color):
        if not cls._ENABLED:
            return text
        return f"{color}{text}{cls.RESET}"

    @classmethod
    def severity(cls, level):
        mapping = {
            "safe": cls.GREEN,
            "low": cls.CYAN,
            "medium": cls.YELLOW,
            "high": cls.MAGENTA,
            "critical": cls.RED,
        }
        return mapping.get(str(level).lower(), cls.WHITE)

    @classmethod
    def title(cls, text):
        return cls.wrap(text, f"{cls.BOLD}{cls.BRIGHT_BLUE}")

    @classmethod
    def accent(cls, text):
        return cls.wrap(text, cls.BRIGHT_CYAN)

    @classmethod
    def success(cls, text):
        return cls.wrap(text, cls.BRIGHT_GREEN)

    @classmethod
    def warning(cls, text):
        return cls.wrap(text, cls.BRIGHT_YELLOW)

    @classmethod
    def error(cls, text):
        return cls.wrap(text, cls.BRIGHT_RED)

    @classmethod
    def dim(cls, text):
        return cls.wrap(text, cls.DIM)
