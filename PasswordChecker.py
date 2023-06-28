import re

def check_password_strength(password):
    # Define the criteria and weights
    criteria = [
        (r'.{8,}', "Password should be at least 8 characters long."),
        (r'[a-z]', "Password should contain at least one lowercase letter."),
        (r'[A-Z]', "Password should contain at least one uppercase letter."),
        (r'\d', "Password should contain at least one digit."),
        (r'[!@#$%^&*(),.?":{}|<>]', "Password should contain at least one special character (!@#$%^&*(),.?\":{}|<>).")
    ]
    weights = [1, 1, 1, 1, 1]

    # Calculate the password strength score
    score = sum(weight for (pattern, _), weight in zip(criteria, weights) if re.search(pattern, password))

    if score == len(criteria):
        return "Strong: Password meets the minimum requirements."
    else:
        feedback = [feedback for _, feedback in criteria if not re.search(_.pattern, password)]
        return "Weak: {}".format(" ".join(feedback))

# Test the function
password = input("Enter a password: ")
result = check_password_strength(password)
print(result)
