
# coding: utf-8

# # Working with SQLAchemy

# In[25]:

## import modules
import os
from datetime import datetime
from flask import Flask, render_template, url_for, request, redirect, flash

## import flaks wtf module
from flask_wtf import Form
from wtforms.fields import StringField, PasswordField, BooleanField, SubmitField
from flask.ext.wtf.html5 import URLField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, url, ValidationError


## import sqlachemy
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

## import flask-login
from flask_login import LoginManager
from flask_login import login_required, login_user, logout_user, current_user
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash


# In[26]:

## initiate the flask app
app = Flask(__name__)

## flash requires secret_key to carry out sessions
## to get a secret_key
## import os
## os.urandom(24)
app.config['SECRET_KEY'] = b'3\nHO\x00\xdd\xae0B\xae\xa7{}\xa5\xed+ 6\x80\x87\xcaP\xc9\xe2'

## Setting up SQLite database connection
basedir = os.path.abspath(os.path.dirname('__file__'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'thermos.db')
db = SQLAlchemy(app)

## Configure login authentication
login_manager = LoginManager()
login_manager.session_protection = "strong" ## ensure security is strong to avoid password hijacking
login_manager.login_view = "login" ## redirects user to the login page when trying to access an un-authorised page
login_manager.init_app(app)


# In[27]:

## manage.py - this helps in managing the database.
from flask.ext.script import Manager, prompt_bool

manager = Manager(app)

## Create Database
@manager.command
def initdb():
    ## SQLAchemy command to create db
    db.create_all()
    ## Adding default users
    ##db.session.add(User(username="kamparia", email="somideolaoye@gmail.com", password="password"))
    ##db.session.commit()
    print('Initialized the Database')
    
## Drop Database
@manager.command
def dropdb():
    if prompt_bool("Are you sure you want to loose all your data"):
        db.drop_all()
        print('Dropped the database')

## Run script
if __name__ == '__main__':
    manager.run()


# In[28]:

## Class for creating database tables in SQLite
## Create Bookmark table
class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
 
    @staticmethod
    def newest(num):
        return Bookmark.query.order_by(desc(Bookmark.date)).limit(num)

    def __repr__(self):
        return "<Bookmark '{}': '{}'>".format(self.description, self.url)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    bookmarks = db.relationship('Bookmark', backref='user', lazy='dynamic')
    password_hash = db.Column(db.String)

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_by_username(username):
        return User.query.filter_by(username=username).first()

    def __repr__(self):
        return "<User '{}'>".format(self.username)

    
## SQLAlchemy creates a database based on DB 
## db.create_all()
## dropdb()
initdb()


# In[29]:

'''
## Insert record into the database table using SQLAlchemy
## Add User & Bookmark
u=User(username='kamparia', email='somideolaoye@gmail.com')
bk = Bookmark(url="http://facebook.com", date=datetime.utcnow(), description="Facebook Social Network")
db.session.add(u, bk)
db.session.commit()

## Simple queries using SQLAchemy
Bookmark.query.all() ## retrieve all row
Bookmark.query.get(1) ## get by primary key
##Bookmark.query.filter_by(username="kamparia").all() ## query using where clause 
'''


# In[30]:

## form.py
## Class for managing the Flask-WTForms 
class BookmarkForm(Form):
    url = URLField('The URL for your bookmark:', validators=[DataRequired(), url()])
    description = StringField('Add an optional description:', validators=[DataRequired()])

    def validate(self):
        if not self.url.data.startswith("http://") or            self.url.data.startswith("https://"):
            self.url.data = "http://" + self.url.data

        if not Form.validate(self):
            return False

        if not self.description.data:
            self.description.data = self.url.data

        return True
    
class LoginForm(Form):
    username = StringField('Your Username:', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class SignupForm(Form):
    username = StringField('Username',
                    validators=[
                        DataRequired(), Length(3, 80),
                        Regexp('^[A-Za-z0-9_]{3,}$',
                            message='Usernames consist of numbers, letters,'
                                    'and underscores.')])
    password = PasswordField('Password',
                    validators=[
                        DataRequired(),
                        EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    email = StringField('Email',
                        validators=[DataRequired(), Length(1, 120), Email()])
    
    ## Validates email field ensuring that email is not currently existing in DB 
    def validate_email(self, email_field):
        if User.query.filter_by(email=email_field.data).first():
            raise ValidationError('There already is a user with this email address.')

    ## Validates username field ensuring that username is not currently existing in DB 
    def validate_username(self, username_field):
        if User.query.filter_by(username=username_field.data).first():
            raise ValidationError('This username is already taken.')


# In[ ]:

## The function loads user based on provided user_id
@login_manager.user_loader
def load_user(userid):
    return User.query.get(int(userid))

## Index page view
@app.route('/')
@app.route('/index')
@app.route('/home')
def index():
    return render_template('index.html', user=current_user, new_bookmarks=Bookmark.newest(5))

## Users Profile page view
@app.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=current_user,)

## Add Bookmark View
@app.route('/add', methods=['GET', 'POST'])
@login_required #to access the page, the user must be logged-in
def add():
    ## Form validation before submit
    form = BookmarkForm()
    if form.validate_on_submit():
        url = form.url.data
        description = form.description.data
        ## Store form variable to database
        bm = Bookmark(user=current_user, url=url, description=description)
        db.session.add(bm)
        db.session.commit()
        flash("Stored '{}'".format(description))
        return redirect(url_for('index'))
    return render_template('add.html', form=form)

## Login View
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user is not None and user.check_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash("Logged in successfully as {}.".format(user.username))
            # makes sure the user gets redirected to the referral page after login in
            return redirect(request.args.get('next') or url_for('user', username=user.username))
        flash('Incorrect username or password.')
    return render_template("login.html", form=form)

## Sign Up view
@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        ## Save user records from form to DB
        user = User(email=form.email.data,
                    username=form.username.data,
                    password = form.password.data)
        db.session.add(user)
        db.session.commit()
        ## redirect to login page after successful sign-up 
        flash('Welcome, {}! Please login.'.format(user.username))
        return redirect(url_for('login'))
    return render_template("signup.html", form=form)

## Logout View
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

## Error Handling
@app.errorhandler(404) ## 404 error - page not found
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500) ## 500 error - server error
def server_error(e):
    return render_template('500.html'), 500

## initiate the app function
if __name__ == "__main__":
    app.run()


# In[ ]:



