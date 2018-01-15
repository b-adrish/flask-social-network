from flask import Flask, request, render_template, flash, redirect, url_for, session, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy 
from functools import wraps
from flask.ext.cache import Cache
import time 

app = Flask(__name__)

cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_KEY_PREFIX': 'fcache',
    'CACHE_REDIS_HOST': 'localhost',
    'CACHE_REDIS_PORT': '6379',
    'CACHE_REDIS_URL': 'redis://localhost:6379'
    })

app.secret_key = "super secret key"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

@app.route('/')
def index():
	return render_template('home.html')


class User(db.Model):
	
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50))
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(50))

	def __init__(self, name, email, password):
		self.name = name
		self.email = email
		self.password = password

db.create_all()

class Articles(db.Model):
	
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(50))
	text = db.Column(db.String(160))

	def __init__(self, email, text):
		self.email = email
		self.text = text


class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Password', [validators.DataRequired(),
		validators.EqualTo('confirm', message="Passwords do not match")])
	confirm = PasswordField('Confirm Password')


class ArticleForm(Form):
	post = StringField("What's on your mind? :P", [validators.Length(min=1, max=160)])


@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == "POST" and form.validate():

		name = form.name.data
		email = form.email.data
		password = sha256_crypt.encrypt(str(form.password.data))
		db.session.add(User(name, email, password))
		db.session.commit()
		flash("HOORAY REGISTERD.", 'succes')
		print('FUCK')
		return redirect(url_for('index'))

	return render_template('register.html', form=form, header="Register")



@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		email = request.form['email']
		password_candidate = request.form['password']

		result = User.query.filter_by(email=email).first()

		if result:

			password = result.password

			#Compare passwords
			if sha256_crypt.verify(password_candidate, password):
				app.logger.info('PASSWORD CORRECT')
				session['logged_in'] = True
				session['email'] = email


				flash("You are now logged in.")
				return redirect(url_for('newsfeed'))
			else:
				app.logger.info('INCORRECT PASS')
				return render_template('login.html', error='INC PASS')

		else:
			app.logger.info('NO USER')
			return render_template('login.html', error='NO USER')

	return render_template('login.html', header='Login')


def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized. Login In', 'danger')
			return redirect(url_for('login'))
	return wrap



@cache.memoize(timeout=30)
def return_nf():
	posts = Articles.query.all()
	app.logger.info("Fetched from DB")
	return posts 


@app.route('/newsfeed', methods=['GET', 'POST'])
@is_logged_in
def newsfeed():

	posts = []
	if 'logged_in' in session:
		app.logger.info(session['logged_in'])
		app.logger.info(session['email'])
		form = ArticleForm(request.form)
		if request.method == "POST" and form.validate():
			db.session.add(Articles(str(session['email']), form.post.data))
			db.session.commit()
			app.logger.info('fuck yeah')

		if request.method == "POST" and 'del' in request.form:
			app.logger.info(request.form['del'])
			val = int(request.form['del'])
			Articles.query.filter_by(id=val).delete()
			db.session.commit()
			app.logger.info("Deteled Post id = %s" %str(val))
		posts = return_nf()
			
	else:
		app.logger.info("NONE")
	
	return render_template('newsfeed.html', articles=posts, form=form)


@app.route('/logout')
def logout():
	session.clear()
	flash('Logged out !!')
	return redirect(url_for('login'))


if __name__ == "__main__":
	app.run(debug=True)