from .color import Color
from .metadata import (
    BANNER_ART,
    TOOL_AUTHOR,
    TOOL_CONTACT,
    TOOL_NAME,
    TOOL_TAGLINE,
    TOOL_VERSION,
)


def format_about(show_banner=True):
    lines = []
    if show_banner:
        lines.append(Color.accent(BANNER_ART.rstrip("\n")))
    lines.append(Color.title(f"{TOOL_NAME} {TOOL_VERSION}"))
    lines.append(Color.accent(f"Author : {TOOL_AUTHOR}"))
    lines.append(Color.accent(f"Contact: {TOOL_CONTACT}"))
    lines.append(Color.dim(f"{TOOL_TAGLINE}"))
    return "\n".join(lines)


def print_about(show_banner=True):
    print(f"{format_about(show_banner=show_banner)}")
