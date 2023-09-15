# password_security_check
import re

def check_password_strength(password):
    # Initialize the strength score
    strength = 0

    # Check if the password length is at least 8 characters
    if len(password) >= 8:
        strength += 1

    # Check if the password contains both uppercase and lowercase letters
    if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
        strength += 1

    # Check if the password contains at least one digit
    if re.search(r'\d', password):
        strength += 1

    # Check if the password contains at least one special character
    if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\\-]', password):
        strength += 1

    return strength

if __name__ == "__main__":
    password = input("Enter a password: ")
    strength = check_password_strength(password)

    if strength == 0:
        print("Weak password")
    elif strength == 1:
        print("Moderate password")
    elif strength == 2:
        print("Strong password")
    else:
        print("Very strong password")
