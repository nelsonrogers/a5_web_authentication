from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path
import re
import flask_limiter
from flask_limiter.util import get_remote_address

# Use bcrypt for password handling
import bcrypt

salt = b'$2b$12$x88Sl.eQfUSDsgoBSv1Vqu'

PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"

app = Flask(__name__)
# The secret key here is required to maintain sessions in flask
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'
# Initialize Database file if not exists.
if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()

limiter = flask_limiter.Limiter(app, key_func=get_remote_address)


@app.route('/')
def home():
    if session:
        return render_template('loggedin.html')
    return render_template('home.html')


# Display register form
@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register.html')


# Handle registration data
@app.route('/register', methods=['POST'])
def register_post():
    if request.form['password'] != request.form['matchpassword']:
        error = 'Passwords do not match.'
        return render_template('register.html', error=error)
    elif not password_check(request.form['password']):
        error = 'Password must contain at least 8 characters including: 1 digit, 1 symbol, 1 uppercase letter and 1 lowercase letter'
        return render_template('register.html', error=error)
    else:
        # get username in plaintext
        username = request.form['username']
        # get password in bytes
        password = request.form['password'].encode('utf-8')
        # hash password
        hashed = bcrypt.hashpw(password, salt)

        # write username and password to file : https://stackoverflow.com/questions/28385337/python-open-a-file-search-then-append-if-not-exist
        with open(PASSWORDFILE, "r+") as file:
            # check if username is present in the file for each line
            for line in file:
                if username + PASSWORDFILEDELIMITER in line:
                    error = "Username already exists."
                    return render_template('register.html', error=error)
            # username not found in file
            else:
                session['username'] = username
                flash("You are successfuly logged in.")
                # append username and password
                file.write(username + PASSWORDFILEDELIMITER + hashed.decode('utf-8') + "\n")

    return render_template('loggedin.html')


# Display login form
@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')


# Handle login credentials
@app.route('/login', methods=['POST'])
@limiter.limit("10/minute") # maximum of 10 requests per minute --> Block dictionary attacks
def login_post():
    username = request.form["username"]
    pwd = request.form["password"].encode('utf-8')
    if username and pwd:
        # write username and password to file : https://stackoverflow.com/questions/28385337/python-open-a-file-search-then-append-if-not-exist
        with open(PASSWORDFILE, "r") as file:
            # check if username is present in the file for each line
            hashed = bcrypt.hashpw(pwd, salt).decode('utf-8')
            for line in file:
                if (username + PASSWORDFILEDELIMITER + hashed) in line:
                    session['username'] = username
                    flash("You are successfuly logged in.")
                    return redirect('/')
            # username not found in file
            else:
                error = "invalid credentials"
                return render_template('login.html', error=error)
    else:
        error = "missing credentials"
        return render_template('login.html', error=error)


@app.route('/logout', methods=['GET'])
def log_out():
    session.clear()
    return redirect('/')


def password_check(password):
    """
    Check the strength of a given password with regular expressions
    Returns boolean: True if password is strong enough
    A password is considered strong if it has a minimum of:
        8 characters length, 1 digit, 1 symbol, 1 uppercase letter, 1 lowercase letter
    """
    # calculating the length
    length_error = len(password) < 8
    # searching for digits
    digit_error = re.search(r"\d", password) is None
    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None
    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None
    # searching for symbols
    symbol_error = re.search(r"\W", password) is None

    # boolean: True if password is strong enough, False otherwise
    valid_password = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    return valid_password


if __name__ == '__main__':

    app.run(ssl_context='adhoc')
print('New content')