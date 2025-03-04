from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import openai
from flask_cors import CORS
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# ✅ Allow CORS for Local & Deployed Frontend
CORS(app, resources={r"/*": {"origins": [
    "http://localhost:5173", 
    "https://sentiment-analysis-ui.netlify.app"
]}})

# Configure SQLite Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat_memory.db"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

openai.api_key = os.environ.get('OPENAI_API_KEY')

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' or 'admin'

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("chat_session.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Load User Function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return "Welcome to your dashboard!"



@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")  # Default role is 'user'


    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get("email")).first()
    if user and check_password_hash(user.password,data.get("password")):  # Insecure! Hash it instead!
        login_user(user)
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"error": "Invalid credentials"}), 401



# Get Chat Sessions for the User
@app.route("/sessions", methods=["GET"])
@login_required
def get_sessions():
    sessions = ChatSession.query.filter_by(user_id=current_user.id).all()
    return jsonify([{"id": s.id, "name": s.name, "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S")} for s in sessions])


# Create a New Chat Session
@app.route("/new_session", methods=["POST"])
@login_required
def new_session():
    print(current_user)
    data = request.json
    new_chat_session = ChatSession(user_id=current_user.id, name=data.get("name"))
    db.session.add(new_chat_session)
    db.session.commit()
    return jsonify({"id": new_chat_session.id, "name": new_chat_session.name})

# Get Messages from a Specific Session
@app.route("/get_messages/<int:session_id>", methods=["GET"])
@login_required
def get_messages(session_id):
    messages = Message.query.filter_by(session_id=session_id).all()
    return jsonify([{"message": m.message, "response": m.response, "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for m in messages])

# Chat Route (Handles AI Responses & Saves Memory in a Session)
@app.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.json
    session_id = data.get("session_id")
    user_input = data.get("message")

    if not session_id:
        return jsonify({"error": "Session ID is required"}), 400

    # Retrieve past chat history from the session
    past_chats = Message.query.filter_by(session_id=session_id).all()
    history = "\n".join([f"User: {chat.message}\nAI: {chat.response}" for chat in past_chats])

    # Send prompt with memory
    prompt = f"{history}\nUser: {user_input}\nAI:"
    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": "You are a helpful assistant."}, 
                  {"role": "user", "content": prompt}],
        max_tokens=150
    )

    ai_response = response["choices"][0]["message"]["content"]

    # Save chat in the session
    new_message = Message(session_id=session_id, message=user_input, response=ai_response)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({"response": ai_response})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create the database
    app.run(debug=True)
