import json
import os
import re
import logging
from functools import lru_cache
from typing import List, Optional

logger = logging.getLogger(__name__)

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


@lru_cache(maxsize=4)
def _get_trusted_publisher_paths() -> List[str]:
    return [
        os.path.join(_CURRENT_DIR, "trusted_publishers.json"),
        os.path.join(_CURRENT_DIR, "..", "analysis", "trusted_publishers.json"),
        "signature/trusted_publishers.json",
        "trusted_publishers.json",
    ]


@lru_cache(maxsize=1)
def _load_trusted_publishers() -> List[str]:
    """
    Load trusted publishers list from JSON with fallback path resolution and caching.
    """
    for path in _get_trusted_publisher_paths():
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as file:
                    data = json.load(file)
                    if isinstance(data, list):
                        return [str(item).strip() for item in data if item]
            except Exception as e:
                logger.error("Error loading trusted publishers from %s: %s", path, e)
                continue

    return [
        "Google LLC",
        "Microsoft Corporation",
        "Adobe Inc.",
        "Mozilla Corporation",
        "Oracle America, Inc.",
        "VideoLAN",
        "Notepad++ Team",
        "GitHub, Inc.",
        "AnyDesk Software GmbH",
    ]


def is_trusted_publisher(publisher: Optional[str]) -> bool:
    """
    Determines if a given publisher string matches a trusted publisher in the database.

    Args:
        publisher: Publisher name or Subject string.

    Returns:
        bool: True if the publisher is recognized as trusted, False otherwise.
    """
    if not publisher or not isinstance(publisher, str):
        return False

    cleaned_publisher = publisher.strip()
    if not cleaned_publisher or cleaned_publisher.lower() == "unknown":
        return False

    trusted_list = _load_trusted_publishers()
    pub_lower = cleaned_publisher.lower()

    for company in trusted_list:
        comp_lower = company.strip().lower()
        if not comp_lower:
            continue

        if pub_lower == comp_lower:
            return True

        pattern = r"(?:\b|_)" + re.escape(comp_lower) + r"(?:\b|_)"
        if re.search(pattern, pub_lower):
            return True

    return False
