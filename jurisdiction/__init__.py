from jurisdiction.eu import PROFILE as EU_PROFILE
from jurisdiction.it import PROFILE as IT_PROFILE
from jurisdiction.cz import PROFILE as CZ_PROFILE

PROFILES = {
    "eu": EU_PROFILE,
    "it": IT_PROFILE,
    "cz": CZ_PROFILE,
}


def get_profile(jurisdiction: str) -> dict:
    key = jurisdiction.lower()
    if key not in PROFILES:
        raise ValueError(
            f"Unknown jurisdiction '{jurisdiction}'. "
            f"Valid options: {', '.join(PROFILES)}"
        )
    return PROFILES[key]
