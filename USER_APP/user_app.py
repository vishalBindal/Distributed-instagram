from flask import Flask, redirect, url_for, render_template, request, flash, json
from datetime import date, datetime

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'

@app.route("/login")
def login(name=''):
	return render_template('login.html', name=name)

@app.route("/login", methods=['POST'])
def login_post():
	name = request.form.get('name')
	password = request.form.get('password')
	remember = request.form.get('remember')
	
	m_key, key2_encrypt, error_code = None, None, None
	# TODO: Send request to master to get user if exists

	if error_code == 1:
		flash('Account not found. Please register first.')
		return redirect(url_for('login', name=name))

	elif error_code == 2:
		flash('Incorrect password.')
		return redirect(url_for('login', name=name))

	# TODO: Write m_key and key2_encrypt to local storage

	# TODO: Send request to recover key2_decrypt asynchronously (and write to local storage)

	# TODO: html page for dashboard
	return redirect(url_for('dashboard'))

@app.route("/register")
def register(username=''):
	return render_template('register.html', username=username)

def generate_key_pair():
	pass

@app.route("/register", methods=['POST'])
def register_post():
	username = request.form.get('username')
	password = request.form.get('password')
	
	already_exists = False
	# TODO: Send request to master to check if user exists

	if already_exists:
		flash('An account with given username already exists. Please pick a new username')
		return redirect(url_for('register'))

	key2_encrypt, key2_decrypt = generate_key_pair()
	success, m_key = False, None
	# TODO: Send request to master to create new user with username and password, and register key2_encrypt
	# Send back success code and m_key

	if not success:
		flash('Unsuccessful. Try again')
		return render_template('register.html', username=username)
	
	# TODO: Write m_key and key2_encrypt and key2_decrypt to local storage

	return redirect(url_for('dashboard'))

@app.route("/")
def index():
	return render_template('front_page.html')

# TODO: define more functions as given in doc


if __name__ == "__main__":
	# if not first time then remove this
	app.run(debug=True, port=5022)