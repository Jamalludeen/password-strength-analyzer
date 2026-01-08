import hashlib
import requests

class HIBPChecker:
    API_URL = "https://api.pwnedpasswords.com/range/"

    def check_password(self, password: str):
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            response = requests.get(f"{self.API_URL}{prefix}", timeout=10)
            response.raise_for_status()

            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")

                if hash_suffix == suffix:
                    return True, int(count)
                
            return False, 0
        
        except requests.RequestException as e:
            print(f"Error checking HIBP: {e}")
            return False, -1
        

hibp_checker = HIBPChecker()
result = hibp_checker.check_password("admin")
print(result)
