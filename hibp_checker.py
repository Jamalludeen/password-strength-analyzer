import hashlib
import logging
import requests

# Use a module-level logger so callers can configure verbosity externally.
logger = logging.getLogger(__name__)

# This module uses the k-Anonymity model: only the first 5 SHA-1 hex
# characters are sent to the HIBP API to avoid sending full hashes.

class HIBPChecker:
    API_URL = "https://api.pwnedpasswords.com/range/"
    TIMEOUT_SECONDS = 10

    def check_password(self, password: str) -> tuple[bool, int]:
        """Check whether `password` appears in HIBP pwned passwords.

        Returns a tuple of (breached: bool, count: int). On network errors
        the count is -1.
        """
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            response = requests.get(f"{self.API_URL}{prefix}", timeout=self.TIMEOUT_SECONDS)
            response.raise_for_status()

            for line in response.text.splitlines():
                if ":" not in line:
                    continue

                hash_suffix, count = line.split(":", 1)

                if hash_suffix == suffix:
                    return True, int(count)
                
            return False, 0
        
        except requests.RequestException as e:
            # Network errors should not crash the UI; report via logger.
            logger.debug("Error checking HIBP: %s", e)
            return False, -1


def format_hibp_result(result: tuple[bool, int]) -> str:
    """Return a compact human-readable HIBP result string."""
    breached, count = result
    if count < 0:
        return "HIBP check failed"
    if breached:
        return f"Breached {count} times"
    return "Not found in HIBP"
        
if __name__ == "__main__":
    # Configure simple logging for local debugging when run directly.
    # The sample password is intentionally common so the formatter can show
    # the breached-path output during a quick manual check.
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    hibp_checker = HIBPChecker()
    result = hibp_checker.check_password("admin")
    print(format_hibp_result(result))
