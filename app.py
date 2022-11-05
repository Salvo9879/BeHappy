from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from wtforms import EmailField, PasswordField
from wtforms.validators import DataRequired, email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

import secrets
import base64
import json



#* ====================================================================================================================================================================================================
#* APP CONFIGURATION



app = Flask(__name__) # Initialise the app 
app.config['SECRET_KEY'] = secrets.token_hex() # Creates a key for the apps security department
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Adds certain values/functions to all templates
@app.context_processor
def utility_processor():
    def convert_str(value):
        return str(value)
    return dict(str=convert_str)


# user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return Databases.Users.query.get(user_id)



#* ====================================================================================================================================================================================================
#* DATABASES



class Databases():
    class Users(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String, nullable=False, unique=True)
        password_hash = db.Column(db.String, nullable=False)

        def __repr__(self):
            return f"[ {self.id} ] - {self.email} || {self.password_hash}"

        @property
        def password(self):
            raise AttributeError('Password is not a readable attribute!')

        @password.setter
        def password(self, password):
            self.password_hash = generate_password_hash(password)

        def verify_password(self, password):
            print(self.password_hash)
            return check_password_hash(self.password_hash, password)



#* ====================================================================================================================================================================================================
#* FLASK FORMS


class FormValidators():
    class UserSearch(object):
        def __init__(self, message=None):
            if not message:
                message = 'This email or password is incorrect'
            self.message = message

        def __call__(self, form, field):
            user_email = form.login_email_input.data
            user_query = Databases.Users.query.filter_by(email=user_email).first()

            if not user_query:
                raise ValidationError(self.message)

    class PasswordValidation(object):
        def __init__(self, message=None):
            if not message:
                message = 'This email or password is incorrect'
            self.message = message

        def __call__(self, form, field):
            user_email = form.login_email_input.data
            user_password = field.data
            user_query = Databases.Users.query.filter_by(email=user_email).first()

            if user_query and not user_query.verify_password(user_password):
                raise ValidationError(self.message)

class Forms():
    class LoginForm(FlaskForm):
        """ This form is only to be used with credential logins. 2 fields:
        1) login_email_input - Used for email. This is a required field & will be validated for email credibility .
        2) login_password_input - Used for password. This is a required field. """
        
        login_email_input = EmailField('Email address', validators=[DataRequired(), email(), FormValidators.UserSearch()])
        login_password_input = PasswordField('Password', validators=[DataRequired(), FormValidators.PasswordValidation()])
    


#* ====================================================================================================================================================================================================
#* APP ROUTES



class AppRoutes():
    class Renders():
        @app.route('/r')
        @app.route('/r/<rule>')
        def general_r(rule=''):
            """ Redirects the user based on their authority level. If the current user is authenticated then they will be returned to the dashboard. If the user is not signed in then they will either
            be returned to the index page or the login page. If the url parameter is equal to 'i' (index) then the user will be redirected to the index page. If the url parameter is equal to 'l' 
            (login) then the user will be redirected to the login page """

            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))
            if rule == 'l':
                return redirect(url_for('login'))
            return render_template(url_for('index'))
            

        @app.route('/r/logout_portal')
        @login_required
        def logout_portal():
            # Logs out the user. Should redirect to the index or login page
            logout_user()
            return 'LOGGED OUT SUCCESSFULLY'

    class Credentials():
        @app.route('/login')
        @app.route('/login/<errors>')
        def login(errors=''):
            """ A portal to login to a account. The html form is posted to :func:`AppRoutes.FormRequests.api_login()`. It will be validated. If validation fails, it will redirect to this page with a
            base64 error code. It is then decoded in the backend servers into a dictionary then planted into the html template. """

            print(current_user.is_authenticated)

            if current_user.is_authenticated:
                return redirect(url_for('general_r'))

            login_form = Forms.LoginForm()

            decoded_errors = ''
            if errors:
                decoded_errors = json.loads(base64.b64decode(errors).decode('ascii'))

            return render_template('login.html', login_form=login_form, decoded_errors=decoded_errors)

    class Api():
        class FormRequests():
            @app.route('/api/login', methods=['GET', 'POST'])
            def api_login():
                """ Api login portal for :func:`AppRoutes.Credentials.login()`. This app route has been designed to be only used with :func:`AppRoutes.Credentials.login()`. DO NOT USE THIS ROUTE FOR
                ANY OTHER REASONS. The html form data is posted to this route. It is then validated for possible errors. If errors are returned, this route will redirect the user back to the login 
                form with a base64 encoded error code. To which can be decoded by the recipient route. """

                login_form = Forms.LoginForm()
                if login_form.validate():
                    user = Databases.Users.query.filter_by(email=login_form.login_email_input.data).first()
                    login_user(user)
                    return redirect(url_for('general_r'))

                encoded_errors = base64.b64encode(json.dumps(login_form.errors).encode('ascii'))

                return redirect(url_for('login', errors=encoded_errors))

    class ErrorHandling():
        class HttpResponseErrors():
            @app.errorhandler(401)
            def error401(error):
                """ When a user attempts to connect to a page without being authenticated for login, then a HTTP response error is raised (Error 401). This is taken by the app & redirects users with
                incorrect security levels to the login page """

                return redirect(url_for('login'))

    class General():
        @app.route('/dashboard')
        def dashboard():
            return render_template('dashboard.html')

#* ====================================================================================================================================================================================================
#* RUN APP



if __name__ == '__main__':
    app.run(
        host = '0.0.0.0',
        port = 5000,
        debug = True
    )