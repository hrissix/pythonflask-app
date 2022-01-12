from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt

app=Flask(__name__)
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SECRET_KEY']='key123'

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#the username must be unique, can't have users with the same name

class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(20), nullable=False, unique=True)
    password=db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={"placeholder": "Username"})

    password=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit=SubmitField("SIGN UP")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={"placeholder": "Username"})

    password=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit=SubmitField("LOGIN")

# class PostTweetForm(Form):
#     tweet = StringField(
#         'Tweet',
#         validators=[DataRequired(), Length(min=6, max=140)]
#     )


@app.route('/')
def home():
    return render_template('index2.html')

#login method, validator hecks if the user and password match with the data if so the user is redirected to the dashboard
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#creating funtion for users to register, the validator hashes the password
@app.route('/register', methods=['GET', 'POST'])
def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# creating routes for pages, some require the user to have logged in
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    flash("What's your name?")
    return render_template('profile.html')

@app.route('/greet', methods=['GET', 'POST'])
@login_required
def greet():
    flash("Hello " + str(request.form['name_input'])+", great to see you!")
    return render_template('profile.html')

@app.route('/explore', methods=['GET', 'POST'])
@login_required
def explore():
    return render_template('explore.html')

#crating the database
if __name__ =='__main__':
    db.create_all()
    app.run(debug=True)
