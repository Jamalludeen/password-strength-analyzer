import random
import string
from dataclasses import dataclass
from typing import List

"""Small password generator helper:
AMBIGUOUS contains characters that can be confusing (e.g. "0" vs "O").
The generator supports options to avoid these and to require at least one
character from each selected set.
"""


@dataclass
class GeneratorOptions:
    length: int = 16
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = False
    require_each_selected: bool = True


class PasswordGenerator:
    AMBIGUOUS = set("0O1lI")
    MIN_LENGTH = 4
    MAX_LENGTH = 128

    def _build_pool(self, options: GeneratorOptions) -> str:
        pool_parts = []

        if options.use_lowercase:
            pool_parts.append(string.ascii_lowercase)
        if options.use_uppercase:
            pool_parts.append(string.ascii_uppercase)
        if options.use_digits:
            pool_parts.append(string.digits)
        if options.use_symbols:
            pool_parts.append("!@#$%^&*()-_=+[]{};:,.?/\\|~")

        pool = "".join(pool_parts)
        if options.avoid_ambiguous:
            pool = "".join(ch for ch in pool if ch not in self.AMBIGUOUS)

        return pool

    def _selected_groups(self, options: GeneratorOptions) -> List[str]:
        groups = []

        if options.use_lowercase:
            groups.append(string.ascii_lowercase)
        if options.use_uppercase:
            groups.append(string.ascii_uppercase)
        if options.use_digits:
            groups.append(string.digits)
        if options.use_symbols:
            groups.append("!@#$%^&*()-_=+[]{};:,.?/\\|~")

        if options.avoid_ambiguous:
            groups = ["".join(ch for ch in group if ch not in self.AMBIGUOUS) for group in groups]

        return [group for group in groups if group]

    def generate_one(self, options: GeneratorOptions) -> str:
        groups = self._selected_groups(options)
        if not groups:
            raise ValueError("At least one character type must be selected")

        if options.length < self.MIN_LENGTH:
            raise ValueError(f"Length must be at least {self.MIN_LENGTH}")

        if options.length > self.MAX_LENGTH:
            raise ValueError(f"Length must be at most {self.MAX_LENGTH}")

        pool = self._build_pool(options)
        if not pool:
            raise ValueError("Character pool is empty with current options")

        if options.require_each_selected and options.length < len(groups):
            raise ValueError("Length must be at least number of selected character sets")

        chars = []
        if options.require_each_selected:
            for group in groups:
                chars.append(random.choice(group))

        while len(chars) < options.length:
            chars.append(random.choice(pool))

        random.shuffle(chars)
        return "".join(chars)

    def generate_many(self, options: GeneratorOptions, count: int = 5) -> List[str]:
        if count < 1:
            raise ValueError("Count must be at least 1")

        return [self.generate_one(options) for _ in range(count)]


def example_generate() -> List[str]:
    """Return a short sample batch using the default options.

    This helper is safe to import and can be used by REPLs or tests.
    """
    gen = PasswordGenerator()
    opts = GeneratorOptions()
    return gen.generate_many(opts, count=3)

# Validation note: generator enforces minimum length and at least one
# selected character group when `require_each_selected` is enabled.
