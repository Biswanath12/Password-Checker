from flask import Flask, request, render_template_string
import bcrypt
import re
import requests
import hashlib

app = Flask(__name__)

class PasswordChecker:
    def __init__(self, breach_db_url):
        self.breach_db_url = breach_db_url

    def validate_password(self, password, machine_generated=False):
        min_length = 6 if machine_generated else 8
        if len(password) < min_length:
            return False, "Password is too short."

        if len(password) > 64:
            return False, "Password is too long."

        if re.search(r'(.)\1\1\1', password) or re.search(r'01234|12345|23456|34567|45678|56789', password):
            return False, "Password contains sequential or repeated characters."

        if self.is_breached(password):
            return False, "Password is in a breach database."

        context_specific_words = ['service_name', 'username']
        if any(word in password for word in context_specific_words):
            return False, "Password contains context-specific words."

        return True, "Password is valid."

    def is_breached(self, password):
        hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = hashed_password[:5]
        response = requests.get(f'{self.breach_db_url}/{prefix}')
        if response.status_code == 200:
            suffixes = [line.split(':') for line in response.text.splitlines()]
            for suffix, count in suffixes:
                if hashed_password[5:] == suffix:
                    return True
        return False

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed

    def check_password(self, password, hashed):
        return bcrypt.checkpw(password.encode(), hashed)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        checker = PasswordChecker('https://api.pwnedpasswords.com/range')
        valid, message = checker.validate_password(password)

        if valid:
            emoji = "✅ Password is strong and valid!"
        else:
            if "too short" in message:
                emoji = "❌ Password is too short."
            elif "too long" in message:
                emoji = "❌ Password is too long."
            elif "sequential or repeated" in message:
                emoji = "⚠️ Password contains sequential or repeated characters."
            elif "breach" in message:
                emoji = "⚠️ Password is in a breach database."
            elif "context-specific" in message:
                emoji = "⚠️ Password contains context-specific words."
            else:
                emoji = "❌ Password is invalid."

        return render_template_string(template, emoji=emoji)

    return render_template_string(template, emoji="")

template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Password Validator</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background: linear-gradient(to right, #6a11cb, #2575fc);
        }
        .container {
            background: #fff;
            padding: 20px 40px;
            border-radius: 10px;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }
        .input-container {
            position: relative;
            margin-bottom: 20px;
        }
        input[type="password"] {
            width: 100%;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        button {
            background: #6a11cb;
            color: #fff;
            border: none;
            padding: 15px 20px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        button:hover {
            background: #2575fc;
        }
        .emoji {
            font-size: 1.5rem;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Password Validator</h1>
        <form method="POST">
            <div class="input-container">
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit">Validate</button>
        </form>
        <div class="emoji">{{ emoji }}</div>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)
