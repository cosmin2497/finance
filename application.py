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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    #How much money user has in account
    cash_in_account = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]
    #Stocks symbols user has in portofolio
    symbols = db.execute("SELECT symbol FROM transactions WHERE id=:user_id", user_id=session.get("user_id"))
    #I used this array to have distinct stocks symbols, I should have used set(), I know...
    array_symbols=[]
    for i in range( 0, len(symbols), 1):
        if not symbols[i]["symbol"] in array_symbols:
            array_symbols.append(symbols[i]["symbol"])
    #This list holds the total number of a single stock symbol
    array_shares=[]
    for l in range( 0, len(array_symbols), 1):
        shares = db.execute("SELECT SUM (shares) FROM transactions WHERE id=:user_id AND symbol=:symbol",
        user_id=session.get("user_id"),
        symbol=array_symbols[l])[0]["SUM (shares)"]

        array_shares.append(shares)
    #This list holds the name of the company
    array_names=[]
    for j in range(0 ,len(array_symbols), 1):
        array_names.append(lookup(array_symbols[j])["name"])
    #Current price of a specific stock
    array_prices=[]
    for k in range(0 ,len(array_symbols), 1):
        array_prices.append(lookup(array_symbols[k])["price"])

    length_symbols=len(array_symbols)
    #This list holds the total value of a specific stock in user's portofolio
    total_price_per_symbol=[]
    for row in range(length_symbols):
        total_prices_per_symbol = array_prices[row]*array_shares[row]
        total_price_per_symbol.append(total_prices_per_symbol)

 
    total_price_symbol = sum(total_price_per_symbol) #Holds total amount of stocks values in portofolio

    #Cash left in account + total amount of stocks values user has in portofolio
    grand_total = cash_in_account + total_price_symbol

    return render_template("index.html",
    cash_in_account=cash_in_account,
    array_symbols=array_symbols,
    array_names=array_names,
    array_prices=array_prices,
    array_shares=array_shares,
    total_price_per_symbol=total_price_per_symbol,
    length_symbols=length_symbols,
    grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    #User inputs
    shares = request.form.get("shares")
    symbol = request.form.get("symbol")

    if request.method == "POST":
        price = lookup(symbol) #Current price of a specific stock

        symbol = symbol.upper() #Capitalize stock name

        now = datetime.now() #Current time

        #<-- errors
        if not symbol:
            return apology("must provide symbol", 400)

        if not shares:
            return apology("must provide the number of shares", 400)

        if shares.isalpha() == True:
            return apology("the number of shares must be positive integer", 400)

        lista = list(shares)

        if chr(45) in lista:
            return apology("can`t input negative number", 400)

        if chr(46) in lista:
            return apology("can`t input float number", 400)

        if not price:
            return apology("the symbol doesn`t exists", 400)

        #<--END errors
        #How much money user has in account
        cash_in_account = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

        #This 'if' checks if user has enough money to buy
        if cash_in_account > (price["price"] * float(shares)):

        	#Checks how many symbols a user has in portofolio
            len_symbols = db.execute("SELECT symbol FROM transactions WHERE id=:user_id", user_id=session.get("user_id"))
            length_symbols = len(len_symbols)

            #This list holds a list of every symbol the user has traded
            array_symbols=[]
            for i in range(length_symbols):
                array_symbols.append(len_symbols[i]["symbol"])

            #This if checks if the bought stock is already in user's portofolio or not
            if symbol in array_symbols:

            	#This holds how many shares of a single symbol a user has in portofolio
                shares_in = db.execute("SELECT shares FROM transactions WHERE id=:user_id AND symbol=:symbol",
                user_id=session.get("user_id"),
                symbol=symbol)[0]["shares"]

                #Modifies the number of shares 
                update_shares = db.execute("UPDATE transactions SET shares=:modified_shares WHERE id=:user_id AND symbol=:symbol",
                user_id=session.get("user_id"),
                modified_shares = int(shares) + int(shares_in),
                symbol=symbol)

                #Money in account after the stock is bought
                cash_in_account = cash_in_account - price["price"] * float(shares)

                #Modifies user's money in database
                update_cash = db.execute("UPDATE users SET cash=:cash_in_account WHERE id=:user_id",
                cash_in_account=cash_in_account,
                user_id=session.get("user_id"))

                #Inserts data into database about the stock that was bought
                history = db.execute("INSERT INTO history (symbol, shares, price, date, id) VALUES (:symbol, :shares, :price, :date, :user_id)",
                user_id=session.get("user_id"),
                symbol = symbol,
                shares = shares,
                date = now,
                price = price["price"])
            #Else bought stock was not in user's portofolio
            else:
            	#Inserts datas about bought stock
                transactions = db.execute("INSERT INTO transactions (id, symbol, shares, date, price) VALUES (:user_id, :symbol, :shares, :date, :price)",
                user_id = session.get("user_id"),
                symbol = symbol,
                shares = shares,
                date = now,
                price = price["price"])

                #Modifies user's money in database
                cash_in_account = cash_in_account - price["price"] * float(shares)
                update_cash = db.execute("UPDATE users SET cash=:cash_in_account WHERE id=:user_id", cash_in_account=cash_in_account, user_id=session.get("user_id"))

                #Inserts data into database about the stock that was bought
                history = db.execute("INSERT INTO history (symbol, shares, price, date, id) VALUES (:symbol, :shares, :price, :date, :user_id)",
                user_id=session.get("user_id"),
                symbol = symbol,
                shares = shares,
                date = now,
                price = price["price"])

        else:
            return apology("You don`t have enough funds")


        return redirect("/")

    else:

        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    if len(request.args.get("username")) > 0 and username_available(request.args.get("username")):
        return jsonify(True)
    else:
        return jsonify(False)



@app.route("/history")
@login_required
def history():

	#Everything about the transactions history

    history = db.execute("SELECT * FROM history WHERE id=:user_id", user_id=session.get("user_id"))
    length_history = len(history)

    array_history = []
    for row in range(length_history):
        array_history.append(history[row])


    return render_template("history.html",
    length_history = length_history,
    symbol = array_history,
    shares = array_history,
    price = array_history,
    transacted = array_history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    #Forget any user_id
    session.clear()

    #User reached route via POST
    if request.method == "POST":

        #Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        #Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        #Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        #Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        #Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        #Redirect user to home page
        return redirect("/")

    #User reached route via GET
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    #Forget any user_id
    session.clear()

    #Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

    	#This checks informations about a specific stock user has inputted
        quote = lookup(request.form.get("symbol"))

        #error
        if not quote:
            return apology("the symbol doesn`t exist", 400)
        #error
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)



        return render_template("quoted.html",
        name=quote["name"],
        symbol=quote["symbol"],
        price=usd(quote["price"]))

    else:

        return render_template("quote.html")

@app.route("/changepassword", methods=["GET", "POST"])
def changepassword():
    if request.method == "POST":
    	#Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id=session.get("user_id"))

        #Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("current password incorrect", 400)
        #Error if password and password confirmation didn't match
        if request.form.get("new_password") != request.form.get("confirmation"):
            return apology("passwords didn`t match", 400)

        #Modifies database with new password
        db.execute("UPDATE users SET hash = :hashed_password WHERE id = :user_id",
                   user_id=session.get("user_id"),
                   hashed_password=generate_password_hash(request.form.get("new_password")))

        #Log out
        session.clear()

        return redirect("/")
    else:
        return render_template("changepassword.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    #Forget any user_id
    session.clear()

    #User reached route via POST 
    if request.method == "POST":

        #Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        #Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        #Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password again", 400)
        #Ensures passwords did match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords didn`t match")

        #<-- These lines checks if username is already in database 
        usernames = db.execute("SELECT username FROM users")
        length_usernames = len(usernames)

        array_usernames=[]
        for names in range(length_usernames):
            array_usernames.append(usernames[names]["username"])
        #Error
        if request.form.get("username") in array_usernames:
            return apology("Username not available", 400)
        #<-- END
        #Insert data in database
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

        now = datetime.now() #Current time
        #<-- Errors
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        elif not request.form.get("shares"):
            return apology("must provide shares", 400)

        elif int(request.form.get("shares")) < 1:
            return apology("the number of shares must be positive integer", 400)
        #<-- END

        #Holds how many shares user has of a specific symbol
        shares = db.execute("SELECT shares FROM transactions WHERE id=:user_id AND symbol=:symbol",
        user_id=session.get("user_id"),
        symbol=request.form.get("symbol"))[0]["shares"]

        shares_input = int(request.form.get("shares")) #User's input

        price = lookup(request.form.get("symbol")) #Current price of that stock



        #Checks if user has enough shares to sell
        if int(request.form.get("shares")) > int(shares):
            return apology("you don`t have enough shares", 400)
        else:
            #Holds the value obtained after selling
            price_shares = int(request.form.get("shares")) * lookup(request.form.get("symbol"))["price"]

            #Holds how much money user has in account
            cash_in_account = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

            update_cash = price_shares+cash_in_account

            #Modifies how much money the user has after selling
            sell_share= db.execute("UPDATE users SET cash=:cash WHERE id=:user_id",
            cash=update_cash,
            user_id=session.get("user_id"))

            #Modifies the number of shares the user has after selling some of them
            updated_shares = db.execute("UPDATE transactions SET shares=:modified_shares WHERE id=:user_id AND symbol=:symbol",
            user_id=session.get("user_id"),
            modified_shares = int(shares) - int(request.form.get("shares")),
            symbol=request.form.get("symbol"))

            #Holds current amount of shares of a specific symbol
            shares = db.execute("SELECT shares FROM transactions WHERE id=:user_id AND symbol=:symbol",
            user_id=session.get("user_id"),
            symbol=request.form.get("symbol"))[0]["shares"]

            #Inserts into database the transaction
            history = db.execute("INSERT INTO history (symbol, shares, price, date, id) VALUES (:symbol, :shares, :price, :date, :user_id)",
            user_id = session.get("user_id"),
            symbol = request.form.get("symbol"),
            shares = shares_input * (-1),
            date = now,
            price = price["price"])

            #If the number of shares of a specific symbol is 0, deletes the symbol from portofolio
            if int(shares) == 0:
                db.execute("DELETE FROM transactions WHERE id=:user_id AND symbol=:symbol",
                user_id=session.get("user_id"),
                symbol=request.form.get("symbol"))

    else:
        #This 'else' shows to the user what symbols he has in portofolio available for selling
        symbols = db.execute("SELECT symbol FROM transactions WHERE id=:user_id", user_id=session.get("user_id"))

        #List of symbols user has in portofolio
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

def username_available(username):
    '''Return true if username is available, false if not'''
    return len(db.execute("SELECT username FROM users WHERE username = :username", username=username)) == 0


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
