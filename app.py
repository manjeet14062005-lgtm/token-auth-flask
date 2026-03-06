from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret123'

users = {
    "admin": "1234"
}

# Authorization Header
@app.route('/auth-header')
def auth_header():

    auth = request.authorization

    if not auth or not users.get(auth.username) == auth.password:
        return jsonify({"message": "Authentication Failed"}), 401

    return jsonify({"message": "Authorized using Authorization Header"})


# Custom Header
@app.route('/custom-header')
def custom_header():

    username = request.headers.get('username')
    password = request.headers.get('password')

    if users.get(username) == password:
        return jsonify({"message": "Authorized using Custom Header"})

    return jsonify({"message": "Authentication Failed"}), 401

@app.route('/')
def home():
    return "Flask Token Authentication API is running"


# Login to generate JWT
@app.route('/login', methods=['POST'])
def login():

    data = request.json
    username = data.get("username")
    password = data.get("password")

    if users.get(username) == password:

        token = jwt.encode({
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"message": "Invalid Credentials"}), 401


# JWT Protection
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({"message": "Token missing"}), 401

        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({"message": "Token invalid"}), 401

        return f(*args, **kwargs)

    return decorated


@app.route('/jwt-protected')
@token_required
def jwt_protected():
    return jsonify({"message": "JWT Authentication Successful"})


if __name__ == '__main__':
    app.run(debug=True)