# password_generator.py
import random
import string

class PasswordGenerator:
    def __init__(self, length, include_numbers, include_lowercase, include_uppercase, include_symbols, no_duplicates):
        self.length = length
        self.include_numbers = include_numbers
        self.include_lowercase = include_lowercase
        self.include_uppercase = include_uppercase
        self.include_symbols = include_symbols
        self.no_duplicates = no_duplicates

    def generate(self):
        char_pool = ""
        if self.include_numbers:
            char_pool += string.digits
        if self.include_lowercase:
            char_pool += string.ascii_lowercase
        if self.include_uppercase:
            char_pool += string.ascii_uppercase
        if self.include_symbols:
            char_pool += string.punctuation

        if not char_pool:
            return "No character set selected"

        password = self._generate_password(char_pool)

        if self.no_duplicates:
            password = self._remove_duplicates(password)

        return password

    def _generate_password(self, char_pool):
        return ''.join(random.choice(char_pool) for _ in range(self.length))

    def _remove_duplicates(self, password):
        return ''.join(sorted(set(password), key=password.index))[:self.length]

