# Esther Koh
# PSet 8
# 11/4/18
# Runs the website

import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Declares variables and asking user for values
    stocks = db.execute("SELECT * FROM purchases WHERE id = :id", id=session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']

    # Calculates the total
    total = sum([float(stock['price'])*float(stock['shares']) for stock in stocks])+float(cash)

    # Calculates the total stock and converts price and total into conventional dollar form
    for stock in stocks:
        stock['price'] = usd(stock['price'])
        stock['total'] = usd(stock['total'])
    return render_template('registered.html', stocks=stocks, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("symbol"):
            return apology("must provide a stock's symbol", 400)

        # Ensure that shares are provided
        if not request.form.get("shares"):
            return apology("must provide shares", 400)

        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("invalid symbol", 400)

        price = lookup(request.form.get("symbol"))['price']

        # Ensures user can afford to buy the shares
        if float(db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']) < int(request.form.get("shares"))*float(price):
            return apology("can't afford", 400)
        db.execute("UPDATE users SET cash=:cash WHERE rowid = :id",
                   cash=float(db.execute("SELECT cash FROM users WHERE id = :id",
                                         id=session["user_id"])[0]['cash'])-int(request.form.get("shares"))*float(price),
                   id=session["user_id"])

        # Adding transaction history
        db.execute("INSERT INTO transactions (id,symbol,name,shares,price) VALUES (:id,:symbol,:name,:shares,:price)",
                   id=session["user_id"],
                   symbol=symbol['symbol'],
                   name=symbol['name'],
                   shares=request.form.get("shares"),
                   price=price)

        # If no current ownership of stock, adds stock to number of owned purchases of stock
        if len(db.execute("SELECT * FROM purchases WHERE id = :id AND symbol LIKE :symbol",
                          id=session["user_id"],
                          symbol=symbol['symbol'])) < 1:
            db.execute("INSERT INTO purchases (id,symbol,name,shares,price,total) VALUES (:id,:symbol,:name,:shares,:price,:total)",
                       id=session["user_id"],
                       symbol=symbol['symbol'],
                       name=symbol['name'],
                       shares=request.form.get("shares"),
                       price=price,
                       total=price*int(request.form.get("shares")))
        # If there is current ownership of stocks, updates the number of owned purchases
        else:
            shares = int(db.execute("SELECT shares FROM purchases WHERE id = :id AND symbol LIKE :symbol",
                                    id=session["user_id"],
                                    symbol=symbol['symbol'])[0]['shares']) + int(request.form.get("shares"))
            db.execute("UPDATE purchases SET shares=:shares, total=:total WHERE id = :id AND symbol LIKE :symbol",
                       shares=shares,
                       total=price*shares,
                       id=session["user_id"],
                       symbol=symbol['symbol'])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    if not request.form.get("username") or len(request.form.get("username")) < 1:
        return apology("must provide username", 403)
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.form.get("username"))
    # Return whether username is available
    return jsonify(len(rows) == 0)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE id = :id", id=session["user_id"])
    for transaction in transactions:
        transaction['price'] = usd(transaction['price'])
    return render_template('history.html', transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/ChangePassword", methods=["GET", "POST"])
@login_required
def ChangePwd():
    """Changes Password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("new") or len(request.form.get("new")) < 1:
            return apology("must provide new password", 403)

        # Ensures password and confirmation matches
        if request.form.get("new") != request.form.get("confirmation"):
            return apology("password and confirmation do not match", 403)

        rows = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])

        # Ensures password is valid
        if not check_password_hash(rows[0]["hash"], request.form.get("old")):
            return apology("invalid password", 403)

        db.execute("UPDATE users SET hash=:hash WHERE id = :id",
                   hash=generate_password_hash(request.form.get("new")),
                   id=session["user_id"])

        # Redirects user
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("ChangePassword.html")


@app.route("/ChangeEmail", methods=["GET", "POST"])
@login_required
def ChangeEm():
    """Changes Email"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensures email address is a new one
        if not request.form.get("new") or len(request.form.get("new")) < 1:
            return apology("must provide new email", 403)

        # Ensures email and confirmation match
        if request.form.get("new") != request.form.get("confirmation"):
            return apology("email and confirmation do not match", 403)

        rows = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])

        # Ensures password is valid
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid password", 403)

        db.execute("UPDATE users SET email=:email WHERE id = :id",
                   email=request.form.get("new"),
                   id=session["user_id"])

        # Redirects user
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("ChangeEmail.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("symbol"):
            return apology("must provide a stock's symbol", 400)

        symbol = lookup(request.form.get("symbol"))

        # Ensures symbol is valid
        if symbol == None:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", symbol=symbol, cost=symbol['price'])

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensures username is provided
        if not request.form.get("username") or len(request.form.get("username")) < 1:
            return apology("must provide username", 403)
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        # Return whether username is available
        if len(rows) == 1:
            return apology("username already exists", 200)
        if not request.form.get("email") or len(request.form.get("email")) < 1:
            return apology("must provide email", 403)
        if not request.form.get("password") or len(request.form.get("password")) < 1:
            return apology("must provide password", 403)
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation do not match", 403)
        db.execute("INSERT INTO users (username, hash, email) VALUES(:username, :hash, :email)",
                   username=request.form.get("username"),
                   hash=generate_password_hash(request.form.get("password")),
                   email=request.form.get("email"))

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Ensures shares are provided
        if not request.form.get("shares"):
            return apology("must provide shares", 400)

        symbol = lookup(request.form.get("symbol"))

        price = lookup(request.form.get("symbol"))['price']
        # Ensures there aren't too many shares
        if int(db.execute("SELECT shares FROM purchases WHERE id = :id AND symbol LIKE :symbol",
                          id=session["user_id"],
                          symbol=symbol['symbol'])[0]['shares']) < int(request.form.get("shares")):
            return apology("too many shares", 400)

        # Adds to transaction history
        db.execute("INSERT INTO transactions (id,symbol,name,shares,price) VALUES (:id,:symbol,:name,:shares,:price)",
                   id=session["user_id"],
                   symbol=symbol['symbol'],
                   name=symbol['name'],
                   shares='-'+request.form.get("shares"),
                   price=price)

        # Updates user shares info
        db.execute("UPDATE users SET cash=:cash WHERE rowid = :id",
                   cash=float(db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"
                                                                                             ])[0]['cash'])+int(request.form.get("shares"))*float(price),
                   id=session["user_id"])
        # If the number of stocks you wish to sell equals the number of stocks you own, it removes the stock from purchases in our table
        if int(db.execute("SELECT shares FROM purchases WHERE id = :id AND symbol LIKE :symbol",
                          id=session["user_id"],
                          symbol=symbol['symbol'])[0]['shares']) == int(request.form.get("shares")):
            db.execute("DELETE FROM purchases WHERE id = :id AND symbol LIKE :symbol",
                       id=session["user_id"],
                       symbol=symbol['symbol'])
        else:
            shares = int(db.execute("SELECT shares FROM purchases WHERE id = :id AND symbol LIKE :symbol",
                                    id=session["user_id"],
                                    symbol=symbol['symbol'])[0]['shares']) - int(request.form.get("shares"))
            db.execute("UPDATE purchases SET shares=:shares, total=:total WHERE id = :id AND symbol LIKE :symbol",
                       shares=shares,
                       total=price*shares,
                       id=session["user_id"],
                       symbol=symbol['symbol'])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("sell.html", options=db.execute("SELECT symbol FROM purchases WHERE id = :id",
                                                               id=session["user_id"]))


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
