from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from wtforms import EmailField, PasswordField
from wtforms.validators import DataRequired, email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

import werkzeug.exceptions as http_exceptions

import datetime
import base64
import json
import uuid
import datetime
import logging
import secrets



#* ====================================================================================================================================================================================================
#* LOGGER FILTERS 

class LoggerFilters():
    class LoggingSessionIdFilter(logging.Filter):
        def filter(self, record):
            record.session_id = secrets.token_hex()
            return True


#* ====================================================================================================================================================================================================
#* HELPERS



class Helpers():
    def get_iso_datetime() -> datetime.datetime:
        """ Gets a ISO formatted data. This is due to JavaScript compatibility reasons. """

        return datetime.datetime.now().isoformat()

    def configure_logger(name: str, filename: str, formatter: str = '<- [%(levelname)s - %(levelno)s] | %(asctime)s | Line: %(lineno)d | Via: "%(name)s" | Msg: "%(message)s" | Session ID: "%(session_id)-15s" ->', 
        level: int = logging.INFO) -> logging.Logger:
            """ Configures a logger with the proper settings. This includes:
            1. `name` : This is the name of the logger.
            2. `filename` : This is the file location of where the server wants to place the log file.
            3. `formatter` : How the logging is formatted. This defaults to `<- [%(levelname)s - %(levelno)s] | %(asctime)s | Line: %(lineno)d | Via %(name)s | Msg: %(message)s | ->`
            4. `level` : This is logging level of the logger (restricts the priority of the log). This defaults to `logging.INFO` -> `20` """

            handler = logging.FileHandler(f"logs/{filename}.log")
            handler.setFormatter(logging.Formatter(formatter))

            logger = logging.getLogger(name)
            logger.addFilter(LoggerFilters.LoggingSessionIdFilter())
            logger.setLevel(level)
            logger.addHandler(handler)

            return logger

    def handle_exception(type_, value):
        exceptions_logger.error(f"'{type_}' was raised. Reason: '{value}'.")


    def test_unauthorized(issue):
        if current_user.is_anonymous:
            #! Work out logger
            raise http_exceptions.Unauthorized()

    def login_user_(email, password):
        user_query = Databases.Users.query.filter_by(email=email).first()
        if not user_query:
            # If user doesn't exist.
            raise ''
        
        if not user_query.verify_password(password):
            # If user password is incorrect
            raise ''

        # If user exists & password is correct
        login_user(user_query)

    def logout_user_(email, password):
        pass

#* ====================================================================================================================================================================================================
#* APP CONFIGURATION



app = Flask(__name__) # Initialise the app 
app.config['SECRET_KEY'] = '6cdd5c732ebde73d009837f26951f9a39056d325d47844954c9352e2a4c48895' # Key used for the servers security protocols
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # The database URI 

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

# Logger configuration
db_logger = Helpers.configure_logger(name='db_logger', filename='db')
exceptions_logger = Helpers.configure_logger(name='exception_logger', filename='exceptions', level=logging.ERROR)



#* ====================================================================================================================================================================================================
#* DATABASES



class Databases():
    """ Here all of the applications database models are stored. They all use an sqlalchemy structure & sqlite driver. """

    class Users(db.Model, UserMixin):
        """ This database model stores all the information about the users. Information such as:
        - `id` : This is used by the backend servers to identify a user. This is usually to find the current logged in user in a session. It is also the primary key. By default this method cannot be 
            modified.
        - `email` : This is the human way of identifying a user. It is mainly used in authentication like logging in or signing up to the website. 
        - `password_hash` : This is the hashed version of the users password. We need to store the password for authentication reasons; however for privacy reasons we cannot store the plaintext 
            password - So instead we salt it, hash it & then store it. 
        - `datetime_created` : The ISO formatted datetime of when the user was successfully activated by our internal servers. Essentially, the datetime of when the user signed up.
        - `user_list_metadata` : Probably one of the most essential rows of this database. We need to store all the list & reminder metadata of the user. This is so we can request or modify the users
            list/reminder data. """

        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String, nullable=False, unique=True)
        password_hash = db.Column(db.String, nullable=False)
        datetime_created = db.Column(db.String, nullable=False, default=Helpers.get_iso_datetime())
        user_list_metadata = db.Column(db.JSON, nullable=False, default=json.dumps([]))

        def __repr__(self) -> str:
            """ The printable representation of the `Databases.Users()` class. Formats the repr to the following: `<- [{id}] | {email} | Lists: {get_list_count()} | ->`. """

            return f"<- [{self.id}] | {self.email} | Lists: {self.get_list_count()} ->"


        #* PASSWORD HASHING 
        @property
        def password(self) -> Exception:
            """ Prevents the internal systems from reading this property. """
            raise AttributeError('\'password\' is not a readable attribute!')

        @password.setter
        def password(self, password: str) -> None:
            """ When property `password` is set, it is formatted to the hashed value and then returned to the property `password_hash`. """
 
            self.password_hash = generate_password_hash(password)

        def verify_password(self, password: str) -> bool:
            """ Checks a plaintext password against the salted, hashed & stored password. Returns either `True` or `False`. """

            return check_password_hash(self.password_hash, password)


        #* MANAGER FUNCTIONS
        def update_row(self, attribute: str, value: str) -> bool:
            """ Used to update a users row in the database. First it checks whether the user is logged in - i.e., authorized. Then uses the parameters `attribute` is tested, If it exists & is an 
            editable attribute the command will succeed; Else if it doesn't exist or is a non-editable attribute then it will fail by raising `http_exceptions.Forbidden()`; I.e., `HTTP 403`. If the 
            command succeeds then the `attribute` will be assigned the value of parameter `value`. """

            if current_user.is_anonymous:
                db_logger.warning(f"An anonymous user attempted to update the database row: '{attribute} -> {value}'. This request was bounced.") #! Create helper function
                raise http_exceptions.Unauthorized()

            if not getattr(self, attribute, False):
                db_logger.error(f"The server attempted to edit an attribute that does not exist. '{attribute} -> {value}'.")
                raise AttributeError(f"Attribute {attribute} does not exist!") #? Create custom exception to return the error code to the user

            if attribute in {'id', 'password_hashed', 'datetime_created'}:
                db_logger.error(f"The server attempted to edit a forbidden attribute. '{attribute}' -> '{value}'. This request was bounced.")
                raise http_exceptions.Forbidden()

            setattr(self, attribute, value)

            db.session.commit()

            db_logger.info(f"Successfully updated row in database: 'Users/{str(current_user.get_id())}/{attribute}' is now set to: '{value}'")

            return True

        def get_user_list_metadata(self) -> str:
            """ Returns the `user_list_metadata` in a json format. """

            """ if current_user.is_anonymous:
                raise http_exceptions.Unauthorized() """

            return json.loads(self.user_list_metadata)



        #* REMINDER FUNCTIONS
        def get_all_reminders(self, list_uuid: str) -> list:
            """ Gets all reminders stored in a list. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Else the list is selected 
            using the parameter `list_uuid`, & then the reminders in said list are returned. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()

            list_metadata = self.get_list(list_uuid)

            return list_metadata['reminders']

        def get_reminder(self, list_uuid: str, reminder_uuid: str) -> dict:
            """ Gets a reminder. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Uses the parameters `list_uuid` and `reminder_uuid` to 
            iterate through all the reminders in that list, then finds the correct one. If a reminder is not found in that list then `Exceptions_.ReminderNotFound()` is raised. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()

            all_reminder_metadata = self.get_all_reminders(list_uuid)

            reminder_query = None
            for reminder in all_reminder_metadata:
                if reminder_uuid == reminder['uuid']:
                    reminder_query = reminder
                    break

            if reminder_query is None:
                raise Exceptions_.ReminderNotFound(f"A reminder with the uuid of '{reminder_uuid}' does not exist!")

            return reminder_query

        def modify_reminder(self, list_uuid: str, reminder_uuid: str, attribute: str, value: str) -> bool:
            """ Modifies a specified reminder. Using the parameters `list_uuid` & `reminder_uuid`. Once it has identified the specified reminder in the specified list. First it will test whether the 
            current_user is signed in. If not `http_exceptions.Unauthorized()` (i.e., HTTP 401) is raised. Else it will test whether the server is attempting to modify a non-editable attribute. If so
            `http_exceptions.Forbidden()` (i.e., HTTP 403) is raised. If parameter `attribute` is editable, then it will be assigned the parameter `value`. The `last_datetime_modified` property will 
            also be assigned to a ISO formatted datetime. This is all committed to the databases. Returns `True` if the function is successful. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()
            
            reminder_metadata = self.get_reminder(list_uuid, reminder_uuid)

            if attribute in ['uuid', 'datetime_created']:
                raise http_exceptions.Forbidden(f"'{attribute}' cannot be modified by the internal servers!")

            reminder_metadata[attribute] = value
            reminder_metadata['last_datetime_modified'] = Helpers.get_iso_datetime()

            db.session.commit()

            return True

        def delete_reminder(self, list_uuid: str, reminder_uuid: str) -> bool:
            """ Deletes a specified reminder. Using the parameters `list_uuid` & `reminder_uuid`. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 
            401) is raised. Else, it will get the `user_metadata`, `list_metadata` & `reminder_metadata`. It then creates index values (the location of the list & string in its parent list); then 
            deletes the reminder, adds the new `list_metadata` to the new `user_metadata` & then commits it to the database. Returns `True` if successful. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()

            user_metadata = self.get_user_list_metadata()
            list_metadata = self.get_list(list_uuid)
            reminder_metadata = self.get_reminder(list_uuid, reminder_uuid)

            list_index = user_metadata.index(list_metadata)
            reminder_index = list_metadata['reminders'].index(reminder_metadata)

            user_metadata.pop(list_index)
            list_metadata['reminders'].pop(reminder_index)
            user_metadata.insert(list_index, list_metadata)

            self.update_row('user_list_metadata', json.dumps(user_metadata))

            return True
            


        #* LIST FUNCTIONS
        def get_list(self, list_uuid: str) -> dict:
            """ Simple function which returns the list metadata required. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Then it 
            gets the `user_metadata` from the database. It will then iterate through all the lists until it finds one that has a uuid that matches parameter `lits_uuid`. If the list with the given 
            `list_uuid` cannot be found then exception `Exceptions_.ListNotFound()` is raised. If it is found then that lists metadata is returned to the calling function. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()

            user_metadata = self.get_user_list_metadata()

            list_query = None
            for list_ in user_metadata:
                if list_uuid == list_['uuid']:
                    list_query = list_
                    break

            if list_query is None:
                raise Exceptions_.ListNotFound(f"A list with the uuid of '{list_uuid}' does not exist!")

            return list_query

        def modify_list(self, list_uuid: str, attribute: str, value: str) -> bool:
            """ Modifies the list with the specified `list_uuid`. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Else the system 
            gets the `list_metadata` and then tests whether the `attribute` its attempting to modify is non-editable. If it is, then `http_exceptions.Forbidden()` is raised. Else the given 
            `attribute` is assigned the value of parameter `value`. The property `last_datetime_modified` is then assigned an ISO formatted datetime. This is then committed to the database. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()

            list_metadata = self.get_list(list_uuid)

            if attribute in ['uuid', 'datetime_created']:
                raise http_exceptions.Forbidden(f"'{attribute}' cannot be modified by the internal servers!")

            list_metadata[attribute] = value
            list_metadata['last_datetime_modified'] = Helpers.get_iso_datetime()

            db.session.commit()

            return True

        def delete_list(self, list_uuid: str) -> bool:
            """ Deletes the list with the specified `list_uuid`. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Else the function
            will collect the `user_metadata` & `list_metadata`. It creates an `index` (the location of an item in a given list). We can now delete the list in that index place. This is then committed
            to the database. Returns `True` if successful. """

            if current_user.is_anonymous:
                raise http_exceptions.Unauthorized()

            user_metadata = self.get_user_list_metadata()
            list_metadata = self.get_list(list_uuid)

            index = user_metadata.index(list_metadata)
            user_metadata.pop(index)

            self.update_row('user_list_metadata', json.dumps(user_metadata))

            return True
        
        def get_list_count(self) -> int:
            """ Gets the amount of lists that a user has. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Else gets the 
            `user_metadata` and then returns the length of it. """

            """ if current_user.is_anonymous:
                raise http_exceptions.Unauthorized() """

            user_metadata = self.get_user_list_metadata()
            return len(user_metadata)



#* ====================================================================================================================================================================================================
#* EXCEPTIONS

class Exceptions_():
    """ Any internal exceptions or custom exceptions for this app. """

    class ReminderNotFound(Exception):
        """ Raised when the server attempted to find a reminder that does not exist. """
        pass

    class ListNotFound(Exception):
        """ Raised when the server attempted to find a reminder that does not exist. """
        pass


#* ====================================================================================================================================================================================================
#* LISTS & REMINDERS



class NewList():
    """ A class which creates/formats a new list ready for a user,
    
    Formats the list into a dict (this is later on turned to json). A new list is made up of the following attributes: 
    1. `title` : The title of the list. It is also a parameter so it can be whatever the user wants it to be. However it is optional. If it.s not set, then it defaults to 'Untitled list'.
    2. `description` : The description of the list. It is also a parameter so it can be whatever the user wants it to be. However it is optional. If it's not set then it defaults to empty.
    3. `uuid` : A computational way to identify the list. The uuid is the way that the server can identify this list from the others. For principal reasons this attribute cannot be modified by anyone
        (not even the servers) after the list is created - (non-editable).
    4. `last_datetime_modified` : The last time this list was modified in any way. It is given a ISO formatted datetime for JavaScript compatibility. This attribute should only be modified by the 
        internal servers. 
    5. `date_created` : The datetime this particular list was created. It is formatted as ISO for easy JavaScript compatibility. For principal reasons this attribute cannot be modified by anyone (not
        even the servers) after the list is created - (non-editable). """

    def __init__(self, title: str = 'Untitled list', description: str = '') -> None:
        self.metadata = {
            'title': title,
            'description': description,
            'uuid': str(uuid.uuid4()),
            'last_datetime_modified': Helpers.get_iso_datetime(),
            'datetime_created': Helpers.get_iso_datetime(),
            'reminders': []
        }

    def add_to_user(self) -> bool:
        """ Adds the lists metadata to the users metadata. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Then gets the users 
        metadata. It then appends the list metadata. This is then committed to the database. """

        if current_user.is_anonymous:
            raise http_exceptions.Unauthorized()

        user_query = Databases.Users.query.filter_by(id=current_user.get_id()).first()

        user_metadata = user_query.get_user_metadata()
        user_metadata.append(self.metadata)

        user_query.update_row('user_list_metadata', json.dumps(user_metadata))

        return True

class NewReminder():
    """ A class which creates/formats a new reminder ready for a user,
    
    Formats the reminder into a dict (this is later on turned to json). A new reminder is made up of the following attributes: 
    1. `title` : The title of the reminder. It is also a parameter so it can be whatever the user wants it to be. However it is optional. If it.s not set, then it defaults to 'Untitled reminder'.
    2. `description` : The description of the reminder. It is also a parameter so it can be whatever the user wants it to be. However it is optional. If it's not set then it defaults to empty.
    3. `uuid` : A computational way to identify the reminder. The uuid is the way that the server can identify this list from the others. For principal reasons this attribute cannot be modified by 
        anyone (not even the servers) after the reminder is created - (non-editable).
    4. `completed` : A boolean value which tells us if the user has deemed the reminder as completed. When the reminder is created this is set to `False` by default.
    5. `last_datetime_modified` : The last time this reminder was modified in any way. It is given a ISO formatted datetime for JavaScript compatibility. This attribute should only be modified by the
        internal servers. 
    6. `date_created` : The datetime this particular reminder was created. It is formatted as ISO for easy JavaScript compatibility. For principal reasons this attribute cannot be modified by anyone 
        (not even the servers) after the list is created - (non-editable). """

    def __init__(self, title: str = 'Untitled reminder', description: str = '', completed: bool = False, sub_steps: list = [], links: list = [], due_date: datetime.datetime = None, frequency_table: 
        dict = {}, hashtags: list = []) -> None:

        self.metadata = {
            'title': title,
            'description': description,
            'uuid': str(uuid.uuid4()),
            'completed': completed,
            'last_datetime_modified': Helpers.get_iso_datetime(),
            'datetime_created': Helpers.get_iso_datetime(),
            'sub_steps': sub_steps,
            'links': links,
            'due_date': due_date,
            'frequency_table': frequency_table,
            'hashtags': hashtags 
        }

    def add_to_list(self, list_uuid: str) -> bool:
        """ Adds the reminders metadata to a list. First tests whether the current_user is signed in. If not `http_exceptions.Unauthorized` (i.e., HTTP 401) is raised. Then is gets the 
        `current_user` `user_list_metadata`. Next gets the `list_metadata` using the parameter `list_uuid`. It then creates a `index` variable which stores the location of the `list_metadata` in the 
        `user_metadata`. It edits the attribute `last_datetime_modified` to a ISO formatted datetime. Then appends the reminder metadata (`self.metadata`) to the list. Finally, it commits to the 
        database. Returns `True` if successful. """

        if current_user.is_anonymous:
            raise http_exceptions.Unauthorized()

        user_query = Databases.Users.query.filter_by(id=current_user.get_id()).first()
        user_metadata = user_query.get_user_list_metadata()
        list_metadata = user_query.get_list(list_uuid)

        index = user_metadata.index(list_metadata)
        
        list_metadata['last_datetime_modified'] = Helpers.get_iso_datetime()
        list_metadata['reminders'].append(self.metadata)

        user_metadata[index] = list_metadata

        user_query.update_row('user_list_metadata', json.dumps(user_metadata))

        return True
        

#* ====================================================================================================================================================================================================
#* FLASK FORMS


class FormValidators():
    """ Custom form validators for the applications forms. """

    class UserSearch(object):
        """ Checks whether a user with a specified email address exists. You can set your own message as a parameter. However this is optional & if not set will be automatically set to the default 
        message. When the class is called it will get the email supplied by the user through the form. It will then test whether a user with that email address exists. If not it raises a 
        `ValidationError()` - this will be configured by the form api. If it does exist then the class will pass. """

        def __init__(self, message: str = None) -> None:
            if not message:
                message = 'This email or password is incorrect'
            self.message = message

        def __call__(self, form: dict, _: dict) -> None:
            user_email = form.login_email_input.data
            user_query = Databases.Users.query.filter_by(email=user_email).first()

            if not user_query:
                raise ValidationError(self.message)

    class PasswordValidation(object):
        """ Verifies a password against the user database. You can set your own message as a parameter. However this is optional & if not set will be automatically set to the default message. When 
        the class is called it will get the email & password supplied by the user through the form. It will then test if the user exists & if the password given is incorrect. If so then it will raise
        a `ValidationError()`. The conditional statement is structured like this because if the user doesn't exist then `FromValidators.UserSearch()` will test this. If the user exists and the 
        password is correct then the class has succeeded & will pass. """

        def __init__(self, message: str = None) -> None:
            if not message:
                message = 'This email or password is incorrect'
            self.message = message

        def __call__(self, form: dict, field: dict) -> None:
            user_email = form.login_email_input.data
            user_password = field.data
            user_query = Databases.Users.query.filter_by(email=user_email).first()

            if user_query and not user_query.verify_password(user_password):
                raise ValidationError(self.message)

class Forms():
    class LoginForm(FlaskForm):
        """ Form used with `AppRoutes.Credentials.login()` & its api portal `AppRoutes.Api.FormRequests.api_login()`. Has 2 fields:
        1. `login_email_input` : The email address of the user. This is a required field, must be a valid email & must be attached to an activated user account. 
        2. `login_password_input` : The password to match that account. This is a required field & must be a verified password upon the action of `login_email_input`. """
        
        login_email_input = EmailField('Email address', validators=[DataRequired(), email(), FormValidators.UserSearch()])
        login_password_input = PasswordField('Password', validators=[DataRequired(), FormValidators.PasswordValidation()])
    


#* ====================================================================================================================================================================================================
#* APP ROUTES



class AppRoutes():
    """ The HTTP routes for all the pages & apis of the application. """

    class Renders():
        """ Url endpoints that will redirect the user to a different page based on external circumstances. They may also preform an action too. """

        #? Redo this function 
        @app.route('/r')
        @app.route('/r/<rule>')
        def general_r(rule: str = '') -> str:
            """ Redirects the user based on their authority level. If the current user is authenticated then they will be returned to the dashboard. If the user is not signed in then they will either
            be returned to the index page or the login page. If the url parameter is equal to 'i' (index) then the user will be redirected to the index page. If the url parameter is equal to 'l' 
            (login) then the user will be redirected to the login page """

            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))
            if rule == 'l':
                return redirect(url_for('login'))
            return render_template(url_for('index'))
            

        #? Redo this function 
        @app.route('/r/logout_portal')
        @login_required
        def logout_portal():
            # Logs out the user. Should redirect to the index or login page
            logout_user()
            return 'LOGGED OUT SUCCESSFULLY'

    class Credentials():
        @app.route('/login')
        @app.route('/login/<errors>')
        def login(errors: str = '') -> str:
            """ A html page which acts as a gateway for the user to log into the website. First it checks whether the user is already logged in. If so it redirects the user to the 
            `AppRoutes.General.dashboard()` page. If the `current_user` is not logged in then it completes the following code. Essentially the way that the server communicates errors from the api 
            endpoint to this html page is through url parameters - check the `AppRoutes.Api.FormRequests.api_login()` for documentation on the api side. Anyways, if the server detects an error though
            the url parameters. It will first decode it (it will be `base64`) & set the variable `decoded_errors`. If there isn't any errors then `decoded_errors` will be set to empty. This variable 
            will then be sent top the template in which Jinja template logic will iterate through all the errors & display them accordingly  

            `templates/login.html` Jinja logic:
            ```html  
            {% if decoded_errors %}
                <div id="errors-container">
                    {% for error_name, error_message in decoded_errors.items() %}
                        <p class="error">
                            <span class="error-title">{{ str(login_form[error_name].label).split('>')[1].split('<')[0] }}: </span>
                            <span class="error-description">{{ error_message[0] }}</span>
                        </p>
                     {% endfor %}
                </div>
            {% endif %}
            ```

             """

            if current_user.is_authenticated:
                return redirect(url_for('general_r')) #? Await maintenance on the render

            login_form = Forms.LoginForm()

            decoded_errors = ''
            if errors:
                decoded_errors = json.loads(base64.b64decode(errors).decode('ascii'))

            return render_template('login.html', login_form=login_form, decoded_errors=decoded_errors)

    class Api():
        class FormRequests():
            @app.route('/api/login', methods=['POST'])
            def api_login() -> str:
                """ Api login portal for `AppRoutes.Credentials.login()`. This app route is to be only used with  `AppRoutes.Credentials.login()`. First it gets the login form properties -
                `Forms.LoginForm()`. Then it tests whether the form details have passed the validation process - Check the `FormValidators()` & `Forms.LoginForms()` for more details on how the 
                servers process form data. Anyways, if the data is all verified, then it essentially means that the user has gained successful access to an account. So it scans the database for the 
                users row. Once found the user is logged in, it redirects users to a renderer. However if the form validation fails then it will ask the `login_form` for errors, then encode them 
                using a base64 encoding & assigns this value to `encoded_errors`. Then redirects them to the login page - `AppRoutes.Credentials.login()` - with the `encoded_errors` sent in a url 
                parameter.  """

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
            def error401(error) -> any:
                """ ErrorHandling for HTTP response error : `HTTP 401 - Unauthorized`. This error is raised when a site user attempts to access a internal resource behind a security wall. This 
                usually means that the user is anonymous & needs to be signed in or logged in. If this error is raised, then they are redirected to the login page `AppRoutes.Credentials.login()` """

                return redirect(url_for('login'))

        class ExceptionErrors():
            @app.errorhandler(Exception)
            def exception_error(error):
                error_type, error_value = type(error).__name__, error
                error_code = base64.b64encode(json.dumps({str(error_type): str(error_value)}).encode('ascii'))
                Helpers.handle_exception(error_type, error_value)

                return render_template('exception_error.html', error_code=error_code)

    class General():
        #! Complete documentation
        @app.route('/dashboard')
        @login_required
        def dashboard():
            return render_template('dashboard.html', current_user=current_user, databases=Databases())

        @app.route('/a')
        def test():
            raise AttributeError('lol')
            

#* ====================================================================================================================================================================================================
#* RUN APP



if __name__ == '__main__':
    app.run(
        host = '0.0.0.0',
        port = 5000,
        debug = True
    )