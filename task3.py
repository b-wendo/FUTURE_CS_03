import getpass
import hashlib
import re

# Function to hash a password
def hashed_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Store hashed_passwords in a dictionary
password_store = {}

# List of common passwords (This could be expanded or loaded from a file)
common_passwords = [
    "password", "123456", "qwerty", "letmein", "welcome", "admin", "123456789", "iloveyou", "12345"
]


# Register a new user 
def register_user(username):
    if username in password_store:
        print("Username already exists.")
        return
    
    password = getpass.getpass("Enter Password: ")


    # Check against common passwords (dictionary attack detection)
    if password.lower() in common_passwords:
        print("Your password is too common and vulnerable to dictionary attacks.")
        return
    

    # Password complexity checks
    if len(password) < 8:
        print("Your password is too short.")
        return
    if not re.search(r"[A-Z]", password):
        print("Your password is missing an uppercase letter.")
        return
    if not re.search(r"[a-z]", password):
        print("Your password is missing a lowercase letter.")
        return
    if not re.search(r"[0-9]", password):
        print("Your password is missing a number.")
        return
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Your password is missing a special character.")
        return
    

    print("Strong password.")


    # Store the hashed password only if it passes validation
    password_store[username] = hashed_password(password)
    print("New user successfully created!")

# Verify the new user created
def authenticate_user(username):
    if username not in password_store:
        print("Username not found.")
        return False

    password = getpass.getpass("Enter Password: ")
    user_password = hashed_password(password)  # Hash the entered password

    if password_store[username] == user_password:
        print("Authentication successful!")
        return True
    else:
        print("Authentication failed!")
        return False

# Main program loop
while True:
    action = input("Do you want to (register/login/exit?) ").lower()
    if action == "register":
        user = input("Enter username: ")
        register_user(user)
    elif action == "login":
        user = input("Enter username: ")
        authenticate_user(user)
    elif action == "exit":
        break
    else:
        print("Invalid option")
