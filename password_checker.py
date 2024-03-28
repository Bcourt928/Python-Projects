import re

def check_password_complexity(password):
    length_criteria = len(password) >= 12
    special_char_criteria = bool(re.search(r'[!@#$%^&*()_+=\-{}\[\]:;"\'|\\<,>.?/]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    uppercase_criteria = bool(re.search(r'[A-Z]', password))

    # Check if all criteria are met
    if all([length_criteria, special_char_criteria, number_criteria, uppercase_criteria]):
        return "Strong"
    else:
        return "Weak"

if __name__ == "__main__":
    password = input("Enter your password: ")
    complexity = check_password_complexity(password)
    print("Password complexity:", complexity)
