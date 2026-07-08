"""
A compact list of extremely common / breached passwords used for quick
weak-password detection. In a production deployment this would be backed
by a much larger corpus (e.g. RockYou-derived lists).
"""

COMMON_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "12345", "12345678",
    "111111", "1234567", "123123", "qwerty123", "1q2w3e", "1234567890",
    "0", "abc123", "654321", "123321", "letmein", "iloveyou", "monkey",
    "admin", "welcome", "login", "master", "dragon", "passw0rd",
    "football", "baseball", "trustno1", "sunshine", "princess",
    "solo", "starwars", "freedom", "whatever", "qazwsx", "1qaz2wsx",
    "password1", "password123", "changeme", "default", "administrator",
    "root", "toor", "guest", "test", "temp123", "hello", "hello123",
    "michael", "jennifer", "jordan", "superman", "batman", "shadow",
    "letmein123", "abcd1234", "asdfgh", "zxcvbn", "zxcvbnm", "121212",
    "1122334455", "aaaaaa", "000000", "666666", "123qwe", "p@ssw0rd",
    "p@ssword", "welcome1", "iloveyou1", "charlie", "donald", "george",
    "computer", "internet", "service", "mustang", "access", "flower",
}

# Simple English dictionary subset used to flag dictionary-word passwords.
DICTIONARY_WORDS = {
    "password", "welcome", "sunshine", "dragon", "monkey", "football",
    "baseball", "master", "shadow", "superman", "batman", "princess",
    "freedom", "trust", "love", "hello", "summer", "winter", "spring",
    "autumn", "flower", "tiger", "eagle", "phoenix", "diamond", "silver",
    "golden", "hero", "wizard", "knight", "dragon", "angel", "star",
    "moon", "sun", "ocean", "river", "mountain", "forest", "computer",
}
