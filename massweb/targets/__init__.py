"""Public exports for target-related types."""

from .target import Target
from .crawl_target import CrawlTarget
from .fuzzy_target import FuzzyTarget
from .fuzzy_target_group import FuzzyTargetGroup

__all__ = [
    "Target",
    "CrawlTarget",
    "FuzzyTarget",
    "FuzzyTargetGroup",
]
