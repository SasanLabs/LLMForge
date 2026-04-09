import os


def normalize_prefix(prefix: str) -> str:
    if not prefix:
        return ""
    normalized = "/" + prefix.strip().strip("/")
    return normalized.rstrip("/")


APP_BASE_PATH = normalize_prefix(os.getenv("FACADE_ROUTE_PREFIX", "/llmforge"))