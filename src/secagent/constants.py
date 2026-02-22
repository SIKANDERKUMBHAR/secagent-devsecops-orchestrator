"""Project-wide constants and enums."""

from enum import Enum, IntEnum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    ACTIVE = "active"
    SUPPRESSED = "suppressed"
    BASELINED = "baselined"
    NEW = "new"
    UNCHANGED = "unchanged"


class ExitCode(IntEnum):
    SUCCESS = 0
    POLICY_FAILED = 1
    CONFIG_ERROR = 2
    SCANNER_ERROR = 3
    INTERNAL_ERROR = 4


SCHEMA_VERSION_REPORT = "1.0.0"
SCHEMA_VERSION_BASELINE = "1.0.0"
