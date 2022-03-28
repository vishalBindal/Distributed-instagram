from flask import Flask, redirect, url_for, render_template, request, flash, json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'

# TODO: define more functions as given in doc

if __name__ == "__main__":
	# if not first time then remove this
	app.run(debug=True, port=5022)
    