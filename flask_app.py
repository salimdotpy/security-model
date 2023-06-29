
# A very simple Flask Hello World app for you to get started with...

from flask import Flask, redirect, render_template, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_required, login_user, LoginManager, logout_user, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from collections import deque
from datetime import datetime, timedelta
import re

from collections import deque
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy

class AttackClassifier:
    def __init__(self):
        self.successful_logins = set()
        self.failed_logins = deque()

    def classify_attack(self, ipaddress):
        current_time = datetime.now()
        self.remove_old_failed_logins(current_time)

        if ipaddress in self.successful_logins:
            return 0

        self.failed_logins.append(current_time)

        if self.count_failed_logins() >= 2:
            return 2

        if self.is_interval_less_than_10_seconds():
            return 1

        return 0

    def remove_old_failed_logins(self, current_time):
        while self.failed_logins and self.failed_logins[0] < current_time - timedelta(seconds=10):
            self.failed_logins.popleft()

    def count_failed_logins(self):
        return len(self.failed_logins)

    def is_interval_less_than_10_seconds(self):
        if len(self.failed_logins) >= 2:
            last_failed_time = self.failed_logins[-1]
            first_failed_time = self.failed_logins[0]
            interval = last_failed_time - first_failed_time
            return interval < timedelta(seconds=10)

        return False

app = Flask(__name__)
app.config["DEBUG"] = True

SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="salimdotpy",
    password="1611mysql",
    hostname="salimdotpy.mysql.pythonanywhere-services.com",
    databasename="salimdotpy$comments",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.secret_key = "my first flask application hosted on pythonanywhere"
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    contact = db.Column(db.String(128))
    email = db.Column(db.String(128))
    password = db.Column(db.String(128))
    status = db.Column(db.String(128))
    date = db.Column(db.DateTime, default=datetime.now)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()


class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))
    posted = db.Column(db.DateTime, default=datetime.now)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    commenter = db.relationship('User', foreign_keys=commenter_id)

class Log(db.Model):

    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password = db.Column(db.String(128))
    ipaddress = db.Column(db.String(128))
    time = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20))

class Classification(db.Model):

    __tablename__ = "classifications"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password = db.Column(db.String(128))
    ipaddress = db.Column(db.String(128))
    time = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20))

# Create an instance of the AttackClassifier
classifier = AttackClassifier()

# new and to remove
@app.route('/api/ip', methods=['GET'])
def get_client_ip():
    remote_addr = request.headers['X-Real-IP'], request.headers,
    return f"<h1>Client IP address: {remote_addr}</h1>"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("main_page.html", comments=Comment.query.all())

    if not current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.form["contents"] not in ['', ' ', None, False]:
        comment = Comment(content=request.form["contents"].strip(), commenter=current_user)
        db.session.add(comment)
        db.session.commit()
    return redirect(url_for('index'))

@app.route("/view/", methods=["GET", "POST"])
def view():
    if request.method == "GET":
        if not current_user.is_authenticated:
            return redirect(url_for('index'))
        return render_template("new_one.html")
    return redirect(url_for('index'))

# Define a Flask route to handle new login entries
# @app.route('/login', methods=['POST'])
# def handle_login():
#     # Extract necessary information from the request
#     username = request.form.get('username')
#     password = request.form.get('password')
#     ipaddress = request.remote_addr

#     # Create a new Log entry
#     new_log = Log(username=username, password=password, ipaddress=ipaddress, status='')

#     # Perform attack classification
#     attack_category = classifier.classify_attack(username)

#     if attack_category == 0:
#         classifier.successful_logins.add(username)

#     # Update the status of the Log entry based on the attack category
#     new_log.status = str(attack_category)

#     # Add the new Log entry to the database
#     db.session.add(new_log)
#     db.session.commit()
#     return 'Login processed.'

@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login_page.html", error=False)

    # Extract necessary information from the request
    username = request.form["username"]
    password = request.form["password"]
    ipaddress = request.headers['X-Real-IP'] or request.remote_addr
    user = load_user(username)
    if user is None or not user.check_password(password):
        makelog = Log(username=username, password=password, ipaddress=ipaddress, status=1)
        db.session.add(makelog)
        db.session.commit()
        # Create a new Classification entry
        new_clfctn = Classification(username=username, password=password, ipaddress=ipaddress, status='')
        # Perform attack classification
        attack_category = classifier.classify_attack(ipaddress)

        if attack_category == 0:
            classifier.successful_logins.add(ipaddress)
        else:
            # Update the status of the Log entry based on the attack category
            new_clfctn.status = str(attack_category)
            # Add the new Log entry to the database
            db.session.add(new_clfctn)
            db.session.commit()
        return render_template("login_page.html", error=True)

    login_user(user)
    makelog = Log(username=username, password=password, ipaddress=ipaddress, status=0)
    db.session.add(makelog)
    db.session.commit()
    return redirect(url_for('index'))

@app.route("/signup/", methods=["GET", "POST"])
def signup():
    msg = ''
    if request.method == "POST":
        # Create variables for easy access
        username = request.form['username']
        contact = request.form['contact']
        email = request.form['email']
        password = request.form['password']
        cfmpass = request.form['cfmpass']
        # try:
        checkEmail = User.query.filter_by(email=email).first()
        checkPhone = User.query.filter_by(contact=contact).first()
        # except:
        #     pass
        if not username or not contact or not email or not password or not cfmpass:
            msg = ['Please fill out the form!', 'error']
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = ['Invalid email address!', 'error']
        elif not int(contact) or len(contact) != 11:
            msg = ['Invalid phone number!', 'error']
        elif checkEmail:
            msg = ['This email has been taken, please try another one!', 'error']
        elif checkPhone:
            msg = ['This phone number has been taken, please try another one!', 'error']
        elif password != cfmpass:
            msg = ['Two password does not match!', 'error']
        else:
            passw = generate_password_hash(password)
            user = User(username=username, contact=contact, email=email, password=passw, status=0)
            try:
                db.session.add(user)
                db.session.commit()
                flash('You\'ve registered successfully,  login now please!', ('success', 'check'))
                return redirect(url_for('login'))
            except:
                msg = ['Something went wrong, Please try again!', 'error']
        return render_template("signup_page.html", msg=msg)
    return render_template("signup_page.html", msg=msg)

@app.route("/delete/", methods=["GET", "POST"])
def deleteComment():
    if request.method == "GET":
        db.drop_all()
        #db.session.query(Comment).filter(Comment.content.is_(None), Comment.posted.is_(None)).delete()
        #db.session.commit()
        return 'Droped'#redirect(url_for('view'))

@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))