from pathlib import Path
from typing import Dict, List
import math
import re
import pprint

# Note: entropy is scaled and bucketed into score contributions so that
# the combined length/variety/entropy checks can reach a 0-100 score.

class PasswordAnalyzer:
    def __init__(self):
        self.min_length = 8
        self.base_dir = Path(__file__).resolve().parent
        self.common_passwords = self.load_common_passwords()

    def analyze(self, password: str) -> Dict:
        """
        Main analysis method
        """
        results = {
            'password_length': len(password),
            'score': 0,
            'max_score': 100,
            'checks': {},
            'recommendations': []
        }

        # check for password length
        length_score = min(len(password) * 2, 25)

        results['checks']['length'] = {
            'passed': len(password) >= self.min_length,
            'score': length_score,
            'message': f'Length: {len(password)} characters'
        }

        results['score'] += length_score

        # Character variety checks
        results['score'] += self.check_character_variety(password, results)

        # Entropy calculation
        entropy = self.calculate_entropy(password)
        entropy_rating = self.rate_entropy(entropy)
        # Map entropy rating to a score contribution so total can reach 100
        entropy_score_map = {
            'Very Weak': 0,
            'Weak': 5,
            'Moderate': 15,
            'Strong': 25,
            'Very Strong': 30,
        }
        entropy_score = entropy_score_map.get(entropy_rating, 0)

        results['checks']['entropy'] = {
            'value': round(entropy, 2),
            'rating': entropy_rating,
            'score': entropy_score,
        }

        results['score'] += entropy_score

        # check for common passwords
        is_common = password.lower() in self.common_passwords
        results['checks']['common_passwords'] = {
            'passed': not is_common,
            'message': "Password is common" if is_common else 'Password is unique'
        }

        if is_common:
            results['score'] = max(0, results['score'] - 50)
        
        results['recommendations'] = self.generate_recommendations(results)
        results['strength'] = self.get_strength_label(results['score'])
        results['masked_password'] = self.mask_password(password)
        results['summary'] = self.build_summary(results)

        return results

    def mask_password(self, password: str) -> str:
        if not password:
            return ''

        if len(password) <= 2:
            return '*' * len(password)

        return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"

    def build_summary(self, results: Dict) -> str:
        return (
            f"Score: {results['score']}/100 | "
            f"Strength: {results['strength']} | "
            f"Length: {results['password_length']}"
        )
    
    def load_common_passwords(self) -> set:
        """
        Load common passwords from file
        """
        try:
            with open(self.base_dir / 'data/common_passwords.txt', 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            return set()
    
    def check_character_variety(self, password: str, results: Dict) -> int:
        """
        Check for different character types
        """
        score = 0
        checks = [
            ('lowercase', r'[a-z]', 10),
            ('uppercase', r'[A-Z]', 10),
            ('digits', r'\d', 10),
            ('special', r'[!@#$%^&*(),.?":{}|<>]', 15)
        ]

        for name, pattern, points in checks:
            has_type = bool(re.search(pattern, password))
            results['checks'][name] = {'passed': has_type, 'score': points if has_type else 0}

            if has_type:
                score += points
        return score
        
    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy"""
        if not password:
            return 0
        
        char_count = {}
        for char in password:
            char_count[char] = char_count.get(char, 0) + 1
        
        entropy = 0
        length = len(password)

        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy * length
    
    def rate_entropy(self, entropy: float) -> str:
        # Thresholds chosen heuristically: lower values indicate predictable
        # or repeated-character patterns; higher values imply greater unpredictability.
        # These buckets map entropy to human-readable ratings used elsewhere.
        if entropy < 28:
            return 'Very Weak'
        elif entropy < 36:
            return 'Weak'
        elif entropy < 60:
            return 'Moderate'
        elif entropy < 80:
            return 'Strong'
        return 'Very Strong'
    
    def get_strength_label(self, score: int) -> str:
        if score < 20:
            return 'Very Weak'
        elif score < 40:
            return 'Weak'
        elif score < 60:
            return 'Moderate'
        elif score < 80:
            return 'Strong'
        return 'Very Strong'
    
    def generate_recommendations(self, results: Dict) -> List[str]:
        recommendations = []
        checks = results['checks']

        if not checks.get('length', {}).get('passed'):
            recommendations.append(f'Use at least {self.min_length} characters')
        if not checks.get('uppercase', {}).get('passed'):
            recommendations.append('Add uppercase letters')
        if not checks.get('lowercase', {}).get('passed'):
            recommendations.append('Add lowercase letters')
        if not checks.get('digits', {}).get('passed'):
            recommendations.append('Add numbers')
        if not checks.get('special', {}).get('passed'):
            recommendations.append('Add special characters (!@#$%^&*)')

        return recommendations

        
if __name__ == "__main__":
    pwd_analyz = PasswordAnalyzer()
    result = pwd_analyz.analyze(password="coll/E*&^#c6t")
    pprint.pprint(result)

