from math import floor
from flask_login import current_user, login_user, logout_user, login_required
from flaskproject import app, db, bcrypt, API_key
from flask import redirect, render_template, url_for, flash, request
from flaskproject.forms import LoginForm, RegistrationForm, StockValue, AddMoney, WithdrawMoney, ExchangeMoney
from flaskproject.models import User, Money
import requests
from math import floor

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', title='Homepage')

@app.route("/about")
def about():
    return render_template('about.html', title='About')
    
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Successfully logged in!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'info')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been log out.', 'success')
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    money = Money.query.filter_by(user=current_user).all()
    return render_template('account.html', title='Account', money=money)

@app.route("/check_exchange_rate", methods=['GET', 'POST'])
def check_exchange_rate():
    form = StockValue()
    if form.validate_on_submit():
        try:
            url =  f'https://www.alphavantage.co/query?function=CURRENCY_EXCHANGE_RATE&from_currency={form.fromCurrency.data[:3]}&to_currency={form.toCurrency.data[:3]}&apikey={API_key}'
            r = requests.get(url)
            data = r.json()
            data = data['Realtime Currency Exchange Rate']
            return render_template('check_exchange_rate.html', title='Check stock value', form=form, data=data)
        except:
            flash('Invalid data', 'info')
            return redirect(url_for('check_exchange_rate'))
    return render_template('check_exchange_rate.html', title='Check stock value', form=form)

@app.route("/add_money", methods=['GET', 'POST'])
@login_required
def add_money():
    form = AddMoney()
    current_user_money = Money.query.filter_by(user=current_user).all()
    if form.validate_on_submit():
        for money in current_user_money:
            if money.name == form.currency.data:
                money.amount += form.amount.data
                db.session.commit()
                return redirect(url_for('account'))
        money = Money(name=form.currency.data, amount=form.amount.data, user=current_user)
        db.session.add(money)
        db.session.commit()
        flash(f'{form.amount.data} {form.currency.data} has been added to your account!', 'success')
        return redirect(url_for('account'))
    return render_template('add_money.html', title='Add money', form=form)

@app.route("/withdraw_money", methods=['GET', 'POST'])
@login_required
def withdraw_money():
    form = WithdrawMoney()
    current_user_money = Money.query.filter_by(user=current_user).all()
    form.currency.choices = [curr.name for curr in current_user_money]
    if form.validate_on_submit():
        for money in current_user_money:
            if money.name == form.currency.data:
                if money.amount - form.amount.data > 0:
                    money.amount -= form.amount.data
                    db.session.commit()
                    flash(f'You have withdrawed {form.amount.data} {money.name}', 'success')
                    return redirect(url_for('account'))
                elif money.amount - form.amount.data == 0:
                    db.session.delete(money)
                    db.session.commit()
                    flash(f'You have withdrawed {money.amount} {money.name}', 'success')
                    return redirect(url_for('account'))
                else:
                    flash(f'You dont have enough! You own {money.amount} of {money.name}.', 'info')
                    return redirect(url_for('withdraw_money'))
    return render_template('withdraw_money.html', title='Withdraw money', form=form)

@app.route("/exchange_money", methods=['GET', 'POST'])
@login_required
def exchange_money():
    form = ExchangeMoney()
    current_user_money = Money.query.filter_by(user=current_user).all()
    form.fromCurrency.choices = [curr.name for curr in current_user_money]
    if form.validate_on_submit():
        try:
            done = False
            url =  f'https://www.alphavantage.co/query?function=CURRENCY_EXCHANGE_RATE&from_currency={form.fromCurrency.data[:3]}&to_currency={form.toCurrency.data[:3]}&apikey={API_key}'
            r = requests.get(url)
            data = r.json()
            data = data['Realtime Currency Exchange Rate']
            rate = float(data['5. Exchange Rate'])

            for money in current_user_money:
                if money.name == form.fromCurrency.data:
                    ownedMoney = money
                    break

            if ownedMoney.amount > form.amount.data:
                ownedMoney.amount -= form.amount.data
                db.session.commit()
            elif ownedMoney.amount == form.amount.data:
                db.session.delete(money)
                db.session.commit()
            else:
                flash(f'You dont have enough! You own {ownedMoney.amount} of {ownedMoney.name}.', 'info')
                return redirect(url_for('withdraw_money')) 
            
            amount = floor(form.amount.data*rate)
            for money in current_user_money:
                if money.name == form.toCurrency.data:
                    money.amount += amount
                    done = True
                    break
            
            if done == False:
                money = Money(name=form.toCurrency.data, amount=amount, user=current_user)
                db.session.add(money)
                    
            db.session.commit()
            flash(f'Properly exchanged {form.amount.data} {form.fromCurrency.data} to {amount} {form.toCurrency.data}.', 'success')
            return redirect(url_for('account'))
        except:
            flash('Invalid data', 'info')
            return redirect(url_for('exchange_money'))
    return render_template('exchange_money.html', title='Exchange Money', form=form)