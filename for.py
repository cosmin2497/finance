import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, redirect
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

#current date
now = datetime.now()


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

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

def _sum(total_price_per_symbol, length_total_price):

    return(sum(total_price_per_symbol))

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    cash_in_account = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

    symbols = db.execute("SELECT symbol FROM transactions WHERE id=:user_id", user_id=session.get("user_id"))

    array_symbols=[]
    for i in range( 0, len(symbols), 1):
        if not symbols[i]["symbol"] in array_symbols:
            array_symbols.append(symbols[i]["symbol"])

    array_shares=[]
    for l in range( 0, len(array_symbols), 1):
        shares = db.execute("SELECT SUM (shares) FROM transactions WHERE id=:user_id AND symbol=:symbol", user_id=session.get("user_id"), symbol=array_symbols[l])[0]["SUM (shares)"]
        array_shares.append(shares)

    array_names=[]
    for j in range(0 ,len(array_symbols), 1):
        array_names.append(lookup(array_symbols[j])["name"])

    array_prices=[]
    for k in range(0 ,len(array_symbols), 1):
        array_prices.append(lookup(array_symbols[k])["price"])

    length_symbols=len(array_symbols)

    total_price_per_symbol=[]
    for row in range(length_symbols):
        total_prices_per_symbol = array_prices[row]*array_shares[row]
        total_price_per_symbol.append(total_prices_per_symbol)


    length_total_price = len(total_price_per_symbol)
    total_price_symbol = _sum(total_price_per_symbol, length_total_price)

    grand_total = cash_in_account + total_price_symbol

    return render_template("index.html",
    cash_in_account=cash_in_account,
    array_symbols=array_symbols,
    array_names=array_names,
    array_prices=array_prices,
    array_shares=array_shares,
    length_symbols=length_symbols,
    grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    shares = request.form.get("shares")
    symbol = request.form.get("symbol")
    if request.method == "POST":
        price = lookup(symbol)

        if not symbol:
            return apology("must provide symbol", 403)

        if not shares:
            return apology("must provide the number of shares", 403)

        for char in shares:
            if char.isalpha() == True:
                return apology("the number of shares must be positive integer", 403)

        if int(shares) < 1:
            return apology("the number of shares must be positive integer", 403)

        if not price:
            return apology("the symbol doesn`t exists", 403)

        cash_in_account = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

        #daca suma din portofel nu este mai mica decat pretul unei actiuni * numarul pe care vreau sa il cumpar
        if cash_in_account > (price["price"] * float(shares)):


            transactions = db.execute("INSERT INTO transactions (id, symbol, shares, date, price) VALUES (:user_id, :symbol, :shares, :date, :price)",
            user_id=session.get("user_id"), symbol = symbol, shares = shares, date = now , price = price["price"])

            cash_in_account = cash_in_account - price["price"] * float(shares)

            update_cash = db.execute("UPDATE users SET cash=:cash_in_account WHERE id=:user_id", cash_in_account=cash_in_account, user_id=session.get("user_id"))

        else:
            return apology("You don`t have enough funds")


        return redirect("/")

    else:

        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":


        quote = lookup(request.form.get("symbol"))


        if not quote:
            return apology("the symbol doesn`t exist", 403)

        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)



        return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=usd(quote["price"]))

    else:

        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
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

        elif not request.form.get("confirmation"):
            return apology("must provide password again", 403)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords didn`t match")

        # Insert data in database
        db.execute('INSERT INTO "users" ("id","username","hash") VALUES (NULL, :username, :hashed_password)',
                   username=request.form.get("username"),
                   hashed_password=generate_password_hash(request.form.get("password")))

        return redirect("/login")


    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        elif not request.form.get("shares"):
            return apology("must provide shares", 403)

        elif int(request.form.get("shares")) < 1:
            return apology("the number of shares must be positive integer", 403)

        #shares imi tine suma actiunilor adunate a unui symbol
        shares = db.execute("SELECT SUM (shares) FROM transactions WHERE id=:user_id AND symbol=:symbol",
        user_id=session.get("user_id"), symbol=request.form.get("symbol"))[0]["SUM (shares)"]

        #intra daca cantitatea pe care o introduc sa o vand este mai mica sau egala decat cat detin
        if int(request.form.get("shares")) > int(shares):
            return apology("you don`t have enough shares", 403)
        else:
            #price shares imi tine suma obtinuta din vanzarea a X shareuri la pretul pietei
            price_shares = int(request.form.get("shares")) * lookup(request.form.get("symbol"))["price"]

            #cash in account imi tine cati bani sunt in portofel
            cash_in_account = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

            update_cash = price_shares+cash_in_account


            sell_share= db.execute("UPDATE users SET cash=:cash WHERE id=:user_id",
            cash=update_cash,
            user_id=session.get("user_id"))




    else:
        symbols = db.execute("SELECT symbol FROM transactions WHERE id=:user_id", user_id=session.get("user_id"))

        array_symbols=[]
        for i in range( 0, len(symbols), 1):
            if not symbols[i]["symbol"] in array_symbols:
                array_symbols.append(symbols[i]["symbol"])
        length_array_symbols = len(array_symbols)


        return render_template("sell.html",
        symbol=array_symbols,
        length=length_array_symbols)


    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
