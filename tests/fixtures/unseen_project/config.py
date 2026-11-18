"""Runtime configuration and export target boundaries."""

MAX_INFLIGHT_WEBHOOKS = 8
CONNECT_TIMEOUT_S = 5.0
DEADLINE_SECONDS = 30

# Directories permitted when persisting generated bundle archives.
ALLOWLISTED_EXPORT_TARGETS = ("/var/exports", "/tmp/bundles")
