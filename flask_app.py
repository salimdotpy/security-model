
# A very simple Flask Hello World app for you to get started with...
from apscheduler.schedulers.background import BackgroundScheduler
from fpdf import FPDF

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

from flask import Flask, redirect, render_template, request, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_migrate import Migrate
from flask_login import login_required, login_user, LoginManager, logout_user, UserMixin, current_user
from all_api import my_api
from werkzeug.security import check_password_hash, generate_password_hash
from collections import deque
#from datetime import datetime, timedelta, date
from datetime import datetime, timedelta, timezone, date

import re, numpy as np
import pytz

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config["DEBUG"] = True
app.config["threaded"] = True
scheduler = BackgroundScheduler()
scheduler_started = False

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
    surname = db.Column(db.String(30), default=None)
    gsm = db.Column(db.String(15), default=None)
    dob = db.Column(db.String(20), default=None)
    jambno = db.Column(db.String(20), default=None)
    date = db.Column(db.DateTime, default=datetime.now)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()

class Admin(db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    contact = db.Column(db.String(128))
    email = db.Column(db.String(128))
    password = db.Column(db.String(128))
    date = db.Column(db.DateTime, default=datetime.now)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return self.username
    def to_dict(self):
        return {
            'id':self.id,
            'username': self.username,
            'contact': self.contact,
            'email': self.email,
            'password': self.password,
            'date': self.date
        }

class Setting(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    noOfAttemptFailed = db.Column(db.Integer, default=5)
    timeInterval = db.Column(db.Integer, default=10)
    modeOfPlay = db.Column(db.Integer, default=0)
    reportTime = db.Column(db.String(128), default="Weekly")
    emailResponse = db.Column(db.String(128))
    date = db.Column(db.DateTime, default=datetime.now)
    def to_dict(self):
        return {
            'id': self.id,
            'noOfAttemptFailed': self.noOfAttemptFailed,
            'timeInterval': self.timeInterval,
            'modeOfPlay': self.modeOfPlay,
            'reportTime': self.reportTime,
            'emailResponse': self.emailResponse,
            'date': self.date
        }

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

class Transaction(db.Model):

    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password = db.Column(db.String(128))
    ipaddress = db.Column(db.String(128))
    time = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20))
    attack = db.Column(db.Integer, default=1)
    defence = db.Column(db.Integer, default=1)
    mode = db.Column(db.Integer, default=1)
    type = db.Column(db.String(50), default="Password Guessing")

class Question(db.Model):

    __tablename__ = "questions"

    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(128))
    date = db.Column(db.DateTime, default=datetime.now)
    def to_dict(self):
        return {
            'id':self.id,
            'question': self.question,
            'date': self.date
        }

class Classification(db.Model):

    __tablename__ = "classifications"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password = db.Column(db.String(128))
    ipaddress = db.Column(db.String(128))
    time = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20))
    attack = db.Column(db.Integer, default=1)
    defence = db.Column(db.Integer, default=1)
    mode = db.Column(db.Integer, default=1)
    type = db.Column(db.String(50), default="Password Guessing")

def getDate(plus=1):
    date, time = str(datetime.now()).split()
    h, m, s = time.split(':')
    h = int(h) + plus
    time = ':'.join([str(h), m, s])
    dt = date + ' ' + time
    return dt

class Wastebin(db.Model):

    __tablename__ = "wastebins"

    id = db.Column(db.Integer, primary_key=True)
    binId = db.Column(db.String(50))
    lon = db.Column(db.String(28))
    lat = db.Column(db.String(28))
    level = db.Column(db.String(50))
    seenby = db.Column(db.Text(), default='[]')
    date = db.Column(db.String(40), default=getDate)

    def to_dict(self):
        return {
            'id':self.id,
            'binId': self.binId,
            'lon': self.lon,
            'lat': self.lat,
            'level': self.level,
            'seenby': eval(self.seenby),
            'date': self.date
        }

class binNotify(db.Model):

    __tablename__ = "binnotifys"

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text())
    status = db.Column(db.Boolean, nullable=False, default=False)
    bId = db.Column(db.Integer, db.ForeignKey('wastebins.id'), nullable=True)
    bin = db.relationship('Wastebin', foreign_keys=bId)
    binDate = db.Column(db.String(40), nullable=True)
    date = db.Column(db.String(40), default=datetime.now)
    def to_dict(self):
        return {
            'id':self.id,
            'text': self.text,
            'status': self.status,
            'bId': self.bId,
            'bin': self.bin.to_dict(),
            'binDate': self.binDate,
            'date': self.date
        }

class AttackClassifier:
    def __init__(self):
        setting = Setting.query.get(1)
        self.timeInterval = setting.timeInterval
        self.noOfAttemptFailed = setting.noOfAttemptFailed
        self.successful_logins = set()
        self.failed_logins = deque()

    def classify_attack(self, ip):
        current_time = datetime.now()
        self.remove_old_failed_logins(current_time)
        cnd = self.count_failed_logins() >= self.noOfAttemptFailed
        try:
            low = Classification.query.filter(Classification.ipaddress ==ip).order_by(Classification.id.desc())
        except: low = None
        if ip in self.successful_logins:
            return 0
        self.failed_logins.append(current_time)
        if cnd:
            return 2
        elif len(low.all())>=self.noOfAttemptFailed:
            return 1
        elif len(low.all()) and str(low.first().status) in "12":
            return low.first().status
        return 3

    def remove_old_failed_logins(self, current_time):
        while self.failed_logins and self.failed_logins[0] < current_time - timedelta(seconds=self.timeInterval):
            self.failed_logins.popleft()

    def count_failed_logins(self):
        return len(self.failed_logins)

    def is_interval_less(self):
        if len(self.failed_logins) >= self.noOfAttemptFailed:
            last_failed_time = self.failed_logins[-1]
            first_failed_time = self.failed_logins[0]
            interval = last_failed_time - first_failed_time
            return interval < timedelta(seconds=self.timeInterval)

        return False

# Function for Model
def modelClass():
    # Assuming there are two players and three strategies for each player
    num_players = 2

    # initialise Data
    r=10
    ca1=2; ca2=4
    cd1=3; cd2=6

    # pass in the Model Formulated
    q_0=ca1/r
    q_1=(ca2-ca1)/r
    q_2=1-(ca2/r)
    p_0=1+(cd1-cd2)/r
    p_1=cd1/2*r
    p_2=(2*cd2-3*cd1)/(2*r)

    # Example probabilities associated with a Nash equilibrium
    nash_equilibrium_probs = np.array([[p_0, p_1, p_2], [q_0, q_1, q_2]])

    # Simulate strategies
    chosen_strategies = []
    for player in range(num_players):
        random_num = np.random.random()  # Generate a random number between [0, 1]

        cumulative_probs = np.cumsum(nash_equilibrium_probs[player])
        chosen_strategy = np.argmax(random_num <= cumulative_probs)
        chosen_strategies.append(chosen_strategy)

    return chosen_strategies

# Create a subclass of FPDF
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Cyber Prevention Report | '+str(datetime.now()).split('.')[0], 0, 1, 'C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, 'Page %s' % self.page_no(), 0, 0, 'C')

    def add_table(self, header, data, max_cell_width):
        self.set_font('Arial', 'B', 11)
        cell_height, i = 7, 0
        # Set table header
        for item in header:
            maxc = max_cell_width[i]
            truncated_item = item[:maxc-len(str(item))-3] + '...' if len(str(item)) > maxc-len(str(item)) else item
            self.cell(maxc, cell_height, str(truncated_item), border=1, align='C')
            i+=1
        self.ln()
        # Set table data
        self.set_font('Arial', '', 11)
        for row in data:
            j=0
            for item in row:
                maxc = max_cell_width[j]
                truncated_item = item[:maxc-len(str(item))-3] + '...' if len(str(item)) > maxc-len(str(item)) else item
                self.cell(maxc, cell_height, str(truncated_item), border=1, align='L')
                j+=1
            self.ln()

def generate_pdf(header, data):
    pdf = PDF()
    pdf.add_page()
    # Add the table to the PDF
    pdf.add_table(header, data, [40, 43, 20, 20, 68])
    # pdf.add_table(header, data, [43, 43, 40, 45, 20])
    # Define the file path where the PDF will be saved
    return pdf.output(dest='S')

def send_email(sender_email, sender_password, receiver_email, subject, body, attachment):
    # Create a MIME multipart message
    message = MIMEMultipart()
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = ', '.join(receiver_email)

    # Attach the body of the email
    message.attach(MIMEText(body, 'plain'))

    # Attach the PDF file
    attachment_part = MIMEApplication(attachment, str(datetime.now())+'_login_logs.pdf')
    attachment_part['Content-Disposition'] = f'attachment; filename="{str(datetime.now())}_login_logs.pdf"'
    message.attach(attachment_part)

    # Connect to the SMTP server and send the email
    smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
    smtp_server.starttls()
    smtp_server.login(sender_email, sender_password)
    smtp_server.sendmail(sender_email, receiver_email, message.as_string())
    smtp_server.quit()

def schedule_email():
    setting = Setting.query.get(1)
    report_time = ['Daily', 'Weekly', 'Monthly', 'Yearly']
    # Your login logs retrieval logic here# Define table header and data
    header = ['IP Address', 'Event Time', 'Attack', 'Defence', 'Remark']
    try:
        logs = Classification.query.all()
        data=[]; item=[]
        for log in logs:
            log.status = 'Blocked' if str(log.status) in '12' else 'Not Successful'
            log.attack = 0 if int(log.attack)==3 else log.attack
            item.append(log.ipaddress)
            item.append(log.time)
            item.append(log.attack)
            item.append(log.defence)
            item.append(log.status)
            data.append(item)
            item=[]
    except:
        data = [['None', 'None', 'None', 'None', 'None']]
    # Generate the PDF
    pdf_data = generate_pdf(header, data)

    # Schedule the email to be sent
    sender_email = 'osenikamorudeen36@gmail.com'
    sender_password = 'pwwgffcfjnvrrcon'
    receiver_email = setting.emailResponse #"salimdotpy@gmail.com"
    subject = report_time[int(setting.reportTime)]+' Attack Report'; body = str(datetime.now()).split('.')[0]
    body = f'Please find attached the Attack Report | {body}'
    send_email(sender_email, sender_password, receiver_email, subject, body, pdf_data)

def start_scheduler():
    global scheduler_started, scheduler
    # scheduler = BackgroundScheduler()
    if not scheduler_started:
        schedule_email()
        # scheduler.add_job(schedule_email, 'interval', seconds=20, next_run_time=datetime.now() + timedelta(seconds=5))
        # scheduler.start()
        scheduler_started = False
        return "Scheduler started"
    else:
        return "Scheduler is already running"

def stop_scheduler():
    global scheduler_started, scheduler
    if scheduler_started:
        scheduler.remove_all_jobs()
        scheduler.shutdown()
        scheduler_started = False
        return "Scheduler stopped"
    else:
        return "Scheduler is not running"

def isInjection(user_text):
    # Common SQL injection patterns to check for
    sql_injection_patterns = [
        r"\b(?:select|update|delete|insert|drop|alter|create|truncate|union|exec|xp_cmdshell)\b",
        r"\b(?:\d+\s*=\s*\d+|\d+\s*>\s*\d+|\d+\s*<\s*\d+|\d+\s*['\"]+)",
        r"(?i)(?:(?:(?:n?and|n?or)\s+(?:\d+=[^&]+))|(?:n?and|n?or)\s+\d+=\d+)",
        r"(?i)\bexec(?:ute)?\s*\(",
        r"\b(?:information_schema|schema_name|table_schema|column_name|table_name|tables|columns)\b",
        r"\b(?:mysql\.)?(?:user|password)\b"
    ]

    # Check for SQL injection patterns in the user input
    for pattern in sql_injection_patterns:
        if re.search(pattern, user_text, re.IGNORECASE):
            return "SQL Injection"
    return "Password Guessing"

def check_new_ip(ip):
    try:
        ip = Transaction.query.filter_by(ipaddress=ip).order_by(Transaction.id.desc()).first()
        return ip.status
    except: return False
# all code for api start here
# Register the routes from routes.py
app.register_blueprint(my_api)
# and end her

@app.route("/getdate")
def dd():
    #import pytz
    from datetime import datetime, timedelta
    # Nigeria is UTC+1
    nigeria_offset = timezone(timedelta(hours=20))
    nigeria_time = datetime.now(nigeria_offset)
    datetime_in_Lagos = pytz.timezone('Africa/Lagos').localize(datetime.now())
    return {'systemDate': datetime.now(), 'Date': datetime_in_Lagos, 'mine':nigeria_time}

@app.route("/get-token", methods=["POST","GET"])
def user_token():
    return {'user_token': generate_password_hash(str(datetime.now()))}

@app.route("/waste-bin", methods=["POST","GET"])
def waste_bin():
    if request.method == "POST":
        binId = request.form["binId"]
        lon = request.form["lon"]
        lat = request.form['lat']
        level = request.form['level']
        try:
            db.session.add(Wastebin(binId=binId, lon=lon, lat=lat, level=level))
            db.session.commit()
            return 'wastebin data added succefully!'
        except:
            db.session.rollback()
            return 'Unable to save wastebin data, please try again later'
    else:
        if request.args.get("who") == 'selim':
            binId = request.args.get("binid")
            lon = request.args.get("lon")
            lat = request.args.get('lat')
            level = request.args.get('level')
            try:
                db.session.add(Wastebin(binId=binId, lon=lon, lat=lat, level=level))
                db.session.commit()
                return 'wastebin data added succefully!'
            except Exception as e:
                db.session.rollback()
                return e #'Unable to save wastebin data, please try again later'
        return 'Method not allowed'
@app.route("/waste-report", methods=["POST","GET"])
def waste_report():
    binInfo = Wastebin.query.order_by(Wastebin.id.desc()).all()
    try:
        binInfo = [
            {'id':bin.id,'binId': bin.binId, 'lon': bin.lon, 'lat': bin.lat, 'level': bin.level, 'date': datetime.strptime(bin.date, "%Y-%m-%d %H:%M:%S.%f"), 'seenby': bin.seenby}
            for bin in binInfo
        ]
    except:
        binInfo = []
    return render_template("notify.html", binInfo=binInfo)

@app.route("/waste-map", methods=["POST","GET"])
def waste_map():
    id = request.args.get("id")
    if id:
        bin = Wastebin.query.get(int(id))
        binInfo = [{'id':bin.id,'binId': bin.binId, 'lon': bin.lon, 'lat': bin.lat, 'level': bin.level,'date': datetime.strptime(bin.date, "%Y-%m-%d %H:%M:%S.%f").strftime("%a, %d %b %Y at %I:%M:%S%p")}]
    else:
        binInfo = Wastebin.query.all()#.order_by(Wastebin.id.desc()).all()
        try:
            binInfos = {}
            for bin in binInfo:
                binInfos[f'"{bin.binId}"'] = {'id':bin.id,'binId': bin.binId, 'lon': bin.lon, 'lat': bin.lat, 'level': bin.level,'date': datetime.strptime(bin.date, "%Y-%m-%d %H:%M:%S.%f").strftime("%a, %d %b %Y at %I:%M:%S%p")}
                binInfo = list(binInfos.values())
        except:
            pass
    return render_template("binmap.html", binInfo=binInfo)

@app.route("/notify", methods=["POST","GET"])
def waste_notify():
    binInfo = None
    if request.method == "POST":
        if 'newNotify' in request.get_json():
            data = request.get_json()
            # binId = data["binId"]
            userToken = data["userToken"]
            binDate = data["binDate"]
            getam = Wastebin.query.filter_by(date=binDate).first()#.to_dict()
            sb = [] if len(eval(getam.seenby)) == 0 else eval(getam.seenby)
            try:
                if userToken not in sb:
                    sb.append(userToken)
                    getam.seenby = str(sb)
                    db.session.commit()
                    return {'status': True, 'data': 'added succefully!'}#getam.to_dict()}
                return {'status': False, 'data': getam.to_dict(), 'send': data}
            except Exception as e:
                db.session.rollback()
                return {'status': False, 'data': 'Something went wrong, please try again later! '+ str(e)}
        if 'newBin' in request.get_json():
            bins = Wastebin.query.all()
            seenby = request.get_json()['seenby']
            try:
                newBins = [
                    {'id':bin.id,'binId': bin.binId, 'lon': bin.lon, 'lat': bin.lat, 'level': bin.level, 'date': bin.date, 'seenby': bin.seenby}
                    for bin in bins if seenby not in eval(bin.seenby)
                ]
                # content = [newBins[cnt] for cnt in range(len(newBins)) if cnt < 1 ]
                return newBins
            except Exception as e:
                return {'status': False, 'data': str(e)}
        return {'error': 'Invalid request'}, 400
    return render_template("notify.html", binInfo=binInfo)

# Route to serve the service worker from the root
@app.route('/service-worker.js')
def service_worker():
    return send_from_directory('static', 'service-worker.js')

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

@app.route('/api/start_scheduler', methods=['GET'])
def start_scheduler_endpoint():
    return start_scheduler()

@app.route('/api/stop_scheduler', methods=['GET'])
def stop_scheduler_endpoint():
    return stop_scheduler()

@app.route('/api/send-report', methods=['GET'])
def send_email_report():
    return start_scheduler()
@app.route('/api/send-email', methods=['GET', 'POST'])
def send_me_email():
    try:
        subject = request.args.get("subject")
        body = request.args.get("body")
        sender = 'osenikamorudeen36@gmail.com'
        recipients = request.args.get('recipients')

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipients
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com')
        smtp_server.login(sender, "pwwgffcfjnvrrcon")
        smtp_server.sendmail(sender, recipients, msg.as_string())
        smtp_server.quit()
        return {'msg': 'Email sent successfully!'}
    except:
        return {'error': 'Something went wrong!'}


@app.route("/view/", methods=["GET", "POST"])
def view():
    if request.method == "GET":
        if not current_user.is_authenticated:
            return redirect(url_for('index'))
        return render_template("new_one.html")
    return redirect(url_for('index'))

@app.route("/askquestion/", methods=["GET", "POST"])
def askquestion():
    check_ip = check_new_ip(request.headers['X-Real-IP'])
    admin = Admin.query.get(1)
    question = Question.query.all()
    if str(check_ip) not in '12':
        return redirect(url_for('login'))
    if request.method == "POST" and 'answer' in request.form:
        # Create variables for easy access
        question = Question.query.all()
        stmt = "SELECT * FROM users WHERE "
        i = 0
        for qs in question:
            pre = ' AND ' if i > 0 else ''
            stmt += pre + qs.question + " = '" + request.form[str(qs.question)] + "'"
            i += 1
        get = db.session.execute(stmt).first()
        if get is None:
            flash('Incorrect details supllied', ('danger', 'warning'))
            return redirect(url_for('askquestion'))
        else:
            try:
                rows = db.session.query(Transaction).filter(Transaction.ipaddress == request.headers['X-Real-IP'])
                rows1 = db.session.query(Classification).filter(Classification.ipaddress == request.headers['X-Real-IP'])
                rows.update({Transaction.status: 0, Transaction.time:datetime.now()}, synchronize_session='fetch')
                rows1.update({Classification.status: 0, Classification.time:datetime.now()}, synchronize_session='fetch')
                # rows.delete(); rows1.delete()
                db.session.commit()
            except: pass
            flash('Your account is now activated successfully!', ('success', 'check'))
            return redirect(url_for('login'))
    return render_template("unblock_page.html", check_ip=check_ip, admin=admin, question=question)

# Create an instance of the AttackClassifier
classifier = AttackClassifier()
@app.route("/login/", methods=["GET", "POST"])
def login():
    setting = Setting.query.get(1)
    check_ip = check_new_ip(request.headers['X-Real-IP'])
    classifier.timeInterval = setting.timeInterval
    classifier.noOfAttemptFailed = setting.noOfAttemptFailed
    if request.method == "GET":
        if str(check_ip) =='1' or str(check_ip) =='2':
            return redirect(url_for('askquestion'))
        return render_template("login_page.html")

    if check_ip =='1' or check_ip =='2':
        return redirect(url_for('askquestion'))
    # Extract necessary information from the request
    username = request.form["username"]
    password = request.form["password"]
    ipaddress = request.headers['X-Real-IP']
    user = load_user(username)
    makelog = Log(username=username, password=password, ipaddress=ipaddress, status=0)
    if user is None or not user.check_password(password):
        makelog.status = 1
        db.session.add(makelog)
        db.session.commit()
        # Create a new Classification entry
        new_clfctn = Classification(username=username, password=password, ipaddress=ipaddress, status=0, mode=setting.modeOfPlay,
        attack=0, defence=0, type=None)
        trans = Transaction(username=username, password=password, ipaddress=ipaddress, status='', mode='', attack=0, defence=0, type=None)
        if setting.modeOfPlay==0:
            status, attack = str(modelClass()[1]), classifier.classify_attack(ipaddress)
            try:
                get_trans = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress).first()
            except:
                get_trans = None
            if not get_trans:
                trans = Transaction(username=username, password=password, ipaddress=ipaddress, status=status, mode=setting.modeOfPlay,
                defence=status, attack=attack)
                db.session.add(trans)
                db.session.commit()
            else:
                get_trans.update({Transaction.username:username, Transaction.password:password, Transaction.status: status,
                Transaction.time:datetime.now(), Transaction.defence:status, Transaction.attack:attack}, synchronize_session='fetch')
                db.session.commit()
            new_clfctn.status, new_clfctn.mode, new_clfctn.defence, new_clfctn.attack = status, setting.modeOfPlay, status, attack
            # Add the new classification entry to the database
            db.session.add(new_clfctn)
            db.session.commit()
        else:
            # Perform attack classification
            attack_cat = str(classifier.classify_attack(ipaddress))
            if attack_cat == '0':
                classifier.successful_logins.add(ipaddress)
            elif attack_cat == '3':
                pass
            else:
                try:
                    get_trans = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress).first()
                except:
                    get_trans = None
                if not get_trans:
                    trans = Transaction(username=username, password=password, ipaddress=ipaddress, status=attack_cat, mode=setting.modeOfPlay,
                    defence=attack_cat, attack=attack_cat)
                    db.session.add(trans)
                    db.session.commit()
                else:
                    get_trans.update({Transaction.username:username, Transaction.password:password, Transaction.status: attack_cat,
                    Transaction.time:datetime.now(), Transaction.defence:attack_cat, Transaction.attack:attack_cat}, synchronize_session='fetch')
                    db.session.commit()
                new_clfctn.mode = setting.modeOfPlay
                new_clfctn.status = new_clfctn.defence = new_clfctn.attack = attack_cat
                # Add the new classification entry to the database
                db.session.add(new_clfctn); db.session.commit()
        # Add the new classification entry to the database
        db.session.add(new_clfctn); db.session.commit()
        flash('Incorrect username or password', ('danger', 'warning'))
        return redirect(url_for('login'))
    login_user(user)
    db.session.add(makelog)
    db.session.commit()
    return redirect(url_for('index'))

@app.route("/api/login", methods=['GET', 'POST'])
def api_login():
    username = request.args.get("username")
    password = request.args.get("password")
    ipaddress = request.args.get('ipaddress')
    status = request.args.get('status')
    setting = Setting.query.get(1); attack = classifier.classify_attack(ipaddress)
    attack = 0 if attack == 3 else attack
    try:
        question1, question2 = Question.query.first().question, db.session.execute("select * from questions order by id desc").first().question
    except: pass
    check_ip = 0 if check_new_ip(ipaddress)==False else check_new_ip(ipaddress)
    if str(check_new_ip(ipaddress)) == '0':
        defence_response = 'Released'
    elif str(check_new_ip(ipaddress)) in '12':
        defence_response = 'Blocked'
    else:
        defence_response = 'No Action'
    msg = {'status': str(attack), 'username': username, 'password': password, 'ipaddress': ipaddress,
    'question1': '', 'question2': '', 'defence': str(check_ip), 'modeofplay': setting.modeOfPlay, 'defence_response': defence_response}
    if str(check_ip) =='1' or str(check_ip) =='2':
        msg['question1'], msg['question2'] = question1, question2
        return msg
    classifier.timeInterval = setting.timeInterval
    classifier.noOfAttemptFailed = setting.noOfAttemptFailed
    makelog = Log(username=username, password=password, ipaddress=ipaddress, status=status)
    vunerable = isInjection(password) or isInjection(username)
    if str(status)=='0':
        db.session.add(makelog)
        db.session.commit()
        # Create a new Classification entry
        new_clfctn = Classification(username=username, password=password, ipaddress=ipaddress, status=0, mode=setting.modeOfPlay, attack=0, defence=0, type=vunerable)
        trans = Transaction(username=username, password=password, ipaddress=ipaddress, status='', mode='', attack=0, defence=0, type=vunerable)
        if setting.modeOfPlay==0:
            status = str(modelClass()[1])
            try:
                get_trans = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress).first()
            except:
                get_trans = None
            if not get_trans:
                trans = Transaction(username=username, password=password, ipaddress=ipaddress, status=status, mode=setting.modeOfPlay,
                defence=status, attack=attack)
                db.session.add(trans)
                db.session.commit()
            else:
                #UPDATED
                get_trans.username=username; get_trans.password=password; get_trans.status=status
                get_trans.time=datetime.now(); get_trans.defence=status; get_trans.attack=attack
                db.session.commit()
            new_clfctn.status, new_clfctn.mode, new_clfctn.defence, new_clfctn.attack = status, setting.modeOfPlay, status, attack
            # Add the new classification entry to the database
            msg['status'], msg['defence'] = str(attack), str(status)
            db.session.add(new_clfctn)
            db.session.commit()
        else:
            # Perform attack classification
            attack_cat = str(classifier.classify_attack(ipaddress))
            if attack_cat == '0':
                classifier.successful_logins.add(ipaddress)
            elif attack_cat == '3':
                pass
            else:
                try:
                    get_trans = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress).first()
                except:
                    get_trans = None
                if not get_trans:
                    trans = Transaction(username=username, password=password, ipaddress=ipaddress, status=attack_cat, mode=setting.modeOfPlay,
                    defence=attack_cat, attack=attack_cat)
                    db.session.add(trans)
                    db.session.commit()
                else:
                    get_trans.username=username; get_trans.password=password; get_trans.status=attack_cat
                    get_trans.time=datetime.now()
                    db.session.commit()
                new_clfctn.mode = setting.modeOfPlay
                new_clfctn.status = new_clfctn.defence = new_clfctn.attack = attack_cat
                # Add the new classification entry to the database
                db.session.add(new_clfctn); db.session.commit()
                msg['status'], msg['defence'] = str(attack), str(attack)
        # Add the new classification entry to the database
        db.session.add(new_clfctn); db.session.commit()
        return msg
    db.session.add(makelog)
    db.session.commit()
    return msg

@app.route("/api/unlock", methods=['GET', 'POST'])
def api_unlock():
    msg=''
    ipaddress = request.args.get('ipaddress')
    status = '0' if request.args.get('status') == '1' else '2'
    attack = Transaction.query.filter_by(ipaddress=ipaddress).all()
    if not attack:
        msg = ['An error occur!', 'error']
    else:
        rows = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress)
        rows1 = db.session.query(Classification).filter(Classification.ipaddress == ipaddress)
        rows.update({Transaction.status: status, Transaction.time:datetime.now()}, synchronize_session='fetch')
        rows1.update({Classification.status: status, Classification.time:datetime.now()}, synchronize_session='fetch')
        db.session.commit()
        msg = ['Attack log updated successfully!', 'success']
    return msg
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
        checkEmail = User.query.filter_by(email=email).first()
        checkPhone = User.query.filter_by(contact=contact).first()

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

@app.route("/admin/", methods=["GET", "POST"])
def admin_():
    admin, msg = False, False
    widget = {}
    if 'admin' in session:
        admin = session['admin']
        widget['setting'] = Setting.query.get(1)
        widget['attack'] = Transaction.query.all()
        widget['attack_count'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3').all())
        widget['attack_s_c'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3', Classification.attack>Classification.defence).all())
        widget['today_s_c'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3', Classification.attack>Classification.defence,
        func.DATE(Classification.time) == date.today()).all())
        widget['today_count'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3', func.DATE(Classification.time) == date.today()).all())
        widget['log'], widget['log1'] = Log.query.all(), Classification.query.all()
        widget['question'] = Question.query.all()
        widget['bio_field'] = [bf for bf in User.__table__.c.keys() if bf not in ['id','username','password','date','status']]

    if request.method == "POST" and 'loginBtn' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists
        admins = Admin.query.filter_by(username=username).first()
        if not username or not password:
            msg = ['Please fill out the form!', 'error']
        elif admins is None or not admins.check_password(password):
            msg = ['Invalid Credential', 'error']
        if msg != False:
            flash(msg[0], ('error', 'warning'))
            return redirect(url_for('admin_'))
        session['admin'] = admins.to_dict()
        flash('You\'ve successfully logged in!', ('success', 'check'))
        return redirect(url_for('admin_'))
    return render_template("admin_page.html", admin=admin, msg=msg, widget=widget)

@app.route("/admin/action/", methods=["GET", "POST"])
def admin_settings():
    msg = False
    if 'admin' in session:
        admin = session['admin']
        if request.method == "POST" and 'settingFrm' in request.form:
            # Create variables for easy access
            noOfAttemptFailed = request.form['noOfAttemptFailed']
            timeInterval = request.form['timeInterval']
            modeOfPlay = request.form['modeOfPlay']
            reportTime = request.form['reportTime']
            emailResponse = request.form['emailResponse']
            settings = Setting.query.all()
            if not noOfAttemptFailed or not timeInterval or not modeOfPlay or not reportTime or not emailResponse:
                msg = ['Please fill out the form!', 'error']
            if not settings:
                settings = Setting(noOfAttemptFailed=noOfAttemptFailed, timeInterval=timeInterval,
                modeOfPlay=modeOfPlay, reportTime=reportTime, emailResponse=emailResponse)
                db.session.add(settings)
                db.session.commit()
                msg = ['Settings inserted successfully!', 'success']
            else:
                settings = Setting.query.get(1)
                settings.noOfAttemptFailed = noOfAttemptFailed
                settings.timeInterval = timeInterval
                settings.modeOfPlay = modeOfPlay
                settings.reportTime = reportTime
                settings.emailResponse = emailResponse
                db.session.commit()
                msg = ['Settings updated successfully!', 'success']
            return msg

        if request.method == "POST" and 'profileFrm' in request.form:
            # Create variables for easy access
            username = request.form['username']
            contact = request.form['contact']
            email = request.form['email']
            profile = Admin.query.get(admin['id'])
            #checkEmail = Admin.query.filter_by(email=email).first()
            #checkPhone = Admin.query.filter_by(contact=contact).first()
            if not username or not contact or not email or not profile:
                msg = ['Please fill out the form!', 'error']
            profile.username = username
            profile.contact = contact
            profile.email = email
            db.session.commit()
            msg = ['Profile updated successfully!', 'success']
            admins = Admin.query.filter_by(id=admin['id']).first()
            session['admin'] = admins.to_dict()
            return msg

        if request.method == "POST" and 'changePassFrm' in request.form:
            # Create variables for easy access
            opass = request.form['opass']
            npass = request.form['npass']
            cpass = request.form['cpass']
            profile = Admin.query.get(admin['id'])
            if not opass or not npass or not cpass:
                msg = ['Please fill out the form!', 'error']
            elif npass != cpass:
                msg = ['Two password does not match!', 'error']
            elif not profile.check_password(opass):
                msg = ['Old password does not match!', 'error']
            password = generate_password_hash(npass)
            profile.password = password
            db.session.commit()
            msg = ['Password updated successfully!', 'success']
            admins = Admin.query.filter_by(id=admin['id']).first()
            session['admin'] = admins.to_dict()
            return msg

        if request.method == "POST" and 'BorU' in request.form:
            # Create variables for easy access
            msg=''
            ipaddress = request.form['ipaddress']
            status = request.form['status']
            action = request.form['action']
            attack = Transaction.query.filter_by(ipaddress=ipaddress).all()
            if not attack:
                msg = ['An error occur!', 'error']
            else:
                if action=='d':
                    rows = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress)
                    rows1 = db.session.query(Classification).filter(Classification.ipaddress == ipaddress)
                    rows.delete(); rows1.delete()
                    db.session.commit()
                    msg = ['Attack log deleted successfully!', 'success']
                else:
                    rows = db.session.query(Transaction).filter(Transaction.ipaddress == ipaddress)
                    rows.update({Transaction.status: status}, synchronize_session='fetch')
                    rows1 = db.session.query(Classification).filter(Classification.ipaddress == ipaddress)
                    rows1.update({Classification.status: status}, synchronize_session='fetch')
                    db.session.commit()
                    msg = ['Attack log updated successfully!', 'success']
            return msg
        if request.method == "POST" and 'questionFrm' in request.form:
            # Create variables for easy access
            # allq = Question.query.all()
            id = request.form['id']
            q = request.form['question']
            if id == 'add':
                if not q:
                    return ['Please select question!', 'error']
                questions = Question.query.filter_by(question=q).first()
                if questions:
                    return ['This question already added!', 'error']
                question = Question(question=q)
                db.session.add(question)
                db.session.commit()
                return ['Question added successfully!', 'success']
            else:
                rows = db.session.query(Question).filter(Question.id == id)
                rows.delete()
                db.session.commit()
                return ['Question deleted successfully!', 'success']

    return redirect(url_for('admin_'))

@app.route("/admin/report/<title>")
def admin_reports(title):
    rows = admin = msg = False
    widget = {'user':False}
    if 'admin' in session:
        admin = session['admin']
        widget['setting'] = Setting.query.get(1)
        widget['attack'] = Transaction.query.all()
        widget['attack_count'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3').all())
        widget['attack_s_c'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3', Classification.attack>Classification.defence).all())
        widget['today_s_c'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3', Classification.attack>Classification.defence,
        func.DATE(Classification.time) == date.today()).all())
        widget['today_count'] = len(Classification.query.filter(Classification.status!='0', Classification.attack!='3', func.DATE(Classification.time) == date.today()).all())
        widget['log'], widget['log1'] = Log.query.all(), Classification.query.all()
        widget['question'] = Question.query.all()
        widget['bio_field'] = [bf for bf in User.__table__.c.keys() if bf not in ['id','username','password','date','status']]

        if title == "today-attack":
            rows, title = Classification.query.filter(Classification.status!='0', Classification.attack!='3', func.DATE(Classification.time) == date.today()).all(), 'Today Attack'
        elif title == "all-attack":
            rows, title = Classification.query.filter(Classification.status!='0', Classification.attack!='3').all(), 'All Attack'
        elif title == "today-success-attack":
            rows, title = Classification.query.filter(Classification.status!='0', Classification.attack!='3', Classification.attack>Classification.defence,
            func.DATE(Classification.time) == date.today()).all(), 'Today Successful Attack'
        elif title == "all-success-attack":
            title = 'All Successful Attack'
            rows = Classification.query.filter(Classification.status!='0', Classification.attack!='3', Classification.attack>Classification.defence).all()
        elif title == "all-unsuccessful-attack":
            title = 'All Unsuccessful Attack'
            rows = Classification.query.filter(Classification.status!='0', Classification.attack<=Classification.defence).all()
        elif title == "all-user":
            rows, title = User.query.all(), 'All registered user'
            widget['user'] = True
        else:
            return redirect(url_for('admin_'))
        return render_template("reports_page.html", admin=admin, logs=rows, title=title, widget=widget, msg=msg)
    return redirect(url_for('admin_'))

@app.route("/admin/logout/", methods=["GET", "POST"])
def admin_logout():
    # Remove session data, this will log the admin out
   session.pop('admin', None)
   flash('You have successfully logged out!', ('warning', 'warning'))
   # Redirect to login page
   return redirect(url_for('admin_'))

@app.route("/do-not/delete/", methods=["GET", "POST"])
def deleteComment():
    if request.method == "GET":
        # db.drop_all()
        db.session.query(Comment).filter(Comment.content.is_(None), Comment.posted.is_(None)).delete()
        db.session.commit()
        return 'Droped'#redirect(url_for('view'))

@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))