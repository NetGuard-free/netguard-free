import os
import hashlib
import hmac
import logging
import datetime

logger = logging.getLogger(__name__)

TRIAL_DAYS = 7
_LICENSE_PREFIXES = {"NGHO", "NGEN"}


def _get_secret() -> bytes:
    return os.environ.get("HMAC_SECRET", "").encode()


def verify_license(key: str) -> bool:
    try:
        key = key.strip().upper()
        parts = key.split("-")
        if len(parts) != 6:
            return False
        if parts[0] not in _LICENSE_PREFIXES:
            return False
        checksum = parts[-1]
        key_body = "-".join(parts[1:5])
        expected = hmac.new(
            _get_secret(), key_body.encode(), hashlib.sha256
        ).hexdigest()[:4].upper()
        return hmac.compare_digest(checksum, expected)
    except Exception:
        logger.debug("License verification failed for key starting with %s", key[:8] if key else "None")
        return False


def get_trial_days_left(cfg: dict) -> int:
    """Returns days remaining in trial (0 if expired or no trial_start)."""
    trial_start = cfg.get("trial_start", "")
    if not trial_start:
        return 0
    try:
        start = datetime.datetime.fromisoformat(trial_start.replace("Z", "+00:00"))
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - start).days
        return max(0, TRIAL_DAYS - elapsed)
    except Exception:
        return 0


def get_plan(cfg: dict) -> str:
    key = cfg.get("license_key", "").strip().upper()
    if key and verify_license(key):
        prefix = key.split("-")[0] if "-" in key else ""
        if prefix == "NGEN":
            return "enterprise"
        return "home"
    if cfg.get("trial_start", ""):
        return "trial" if get_trial_days_left(cfg) > 0 else "trial_expired"
    return "free"


def is_paid(plan: str) -> bool:
    return plan in ("home", "enterprise", "trial")


def get_limits(plan: str) -> dict:
    from netguard.models import FREE_LIMITS, HOME_LIMITS, ENTERPRISE_LIMITS
    if plan == "enterprise":
        return ENTERPRISE_LIMITS
    if plan in ("home", "trial"):
        return HOME_LIMITS
    return FREE_LIMITS
