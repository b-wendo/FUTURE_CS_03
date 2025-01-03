# Password Analyzer

A simple password analyzer that helps users register, authenticate, and verify the strength of their passwords. This tool checks if a password is commonly used and provides a secure way to register and authenticate users.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/b-wendo/FUTURE_CS_03

2. Navigate to the project directory
    cd FUTURE3

3. Install the required dependencies
    pip install pyfiglet


## Usage
To run the password analyzer, execute the following command:
    python password_analyzer.py

You will be prompted to either register a new user, log in, or exit the program. Follow the instructions displayed in the terminal.

## Features
- **User Registration**:Allows users to register with a unique username and password.
- **Password Authentication**: Authenticates users by comparing entered passwords with stored, hashed passwords.
- **Common Password Detection**: Prevents the use of commonly used passwords (e.g., "123456", "password", etc.).
- **Secure Password Input**: Uses the getpass module to securely input passwords without displaying them.


## Requirements
1. **getpass**: A module used for securely entering passwords (standard in Python).
2. **hashlib**: Part of Python's standard library, used for securely hashing passwords.
3. **pyfiglet**: A Python library to generate ASCII art text (used for displaying the project title in a stylized format).





 