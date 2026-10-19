"""Small terminal-safe XT-Forge identity banners."""

BANNERS = {
    "compact": "XT-FORGE // DAMASCUS",
    "wide": (
        "╔══════════════════════════════════════╗\n"
        "║  XT-FORGE  /  SYSTEM ACCESS          ║\n"
        "║  MEMORY · ROUTING · BUILD · VERIFY  ║\n"
        "╚══════════════════════════════════════╝"
    ),
    "signal": (
        "[ XT ]────────────────────────[ ONLINE ]\n"
        "     ╲  MEMORY  ──  ROUTE  ──  BUILD  ╱\n"
        "      └────────── DAMASCUS ──────────┘"
    ),
}


def render(style: str = "signal") -> str:
    """Return the named banner; invalid styles raise ValueError."""
    try:
        return BANNERS[style]
    except KeyError as exc:
        raise ValueError(f"unknown ASCII style: {style}") from exc
