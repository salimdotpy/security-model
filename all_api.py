from flask import Blueprint, render_template, request

# Create a Blueprint object
my_api = Blueprint('my_api', __name__)

# Define a route and its corresponding view function
@my_api.route('/hello')
def hello():
    return render_template('hello.html')
@my_api.route("/api/login", methods=["GET", "POST"])
def api_login():
    return f"(real = {request.headers['X-Real-IP']}, add = {request.remote_addr})"

@my_api.route('/api/register', methods=['GET'])
def api_register():
    return "This is api for register"