from datetime import datetime
from flask import Flask, render_template, url_for, redirect, request, session, flash, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit



app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.db"
app.config["SECRET_KEY"] = "heythereitshudahowareyou"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect here if not logged in

socketio = SocketIO(app)
user_connected = False



NAME_KEY = "name"
client = None
messages = []


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"}
    )
    confirm_password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Confirm Password"}
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("[Oops!] Username already exists.")


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"}
    )
    submit = SubmitField("Login")
    
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"Message('{self.from_user}', '{self.time}', '{self.message}')"



# -------------------------- Routes ---------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Displays login page and handles user login authentication.
    """
    if current_user.is_authenticated:
        return redirect(url_for("user_panel"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("user_panel"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Displays user registration page and handles registration.
    """
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RegistrationForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash("Passwords do not match!", "danger")
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for("login"))

    return render_template("register.html", form=form)



def save_message_to_db(username, message_text):
    """
    Save a message to the database and emit it to connected clients.
    """
    global socketio
    
    message = {
        "from": username,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": message_text,
    }

    #save to database
    new_message = Message(from_user=username, time=message["time"], message=message_text)
    db.session.add(new_message)
    db.session.commit()

    # Emitting the message to connected clients
    socketio.emit("receive_message", message)



@app.route("/logout")
@login_required
def logout():
    """Handles user logout and clears session."""
    
    save_message_to_db(current_user.username, "[LEFT]")
    logout_user()    
    flash("Logged out successfully", "success")
    return redirect(url_for("index"))


@app.route("/home")
@login_required
def home():
    """
    Displays main chat panel and ensures the client is initialized.
    """
    return render_template("home.html")


@app.route("/user_panel")
@login_required
def user_panel():
    """
    Displays the user dashboard.
    """
    save_message_to_db(current_user.username, "[JOINED]")
    return render_template("user_panel.html")


@app.route("/")
def index():
    return render_template("index.html")

# ------------------------ Socket Handlers ----------------------------------

@socketio.on("connect")
def handle_connect():
    if current_user.is_authenticated:
        print(f"[CONNECTION] {current_user.username} connected")

@socketio.on("disconnect")
def handle_disconnect():
    if current_user.is_authenticated:
        print(f"[DISCONNECT] {current_user.username} disconnected")
        

@socketio.on("send_message")
def handle_send_message(data):
    """
    Handles message sending and broadcasting.
    """
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    else:
        username = current_user.username
        message_content = data.get("message", "")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create and store the new message in the database
        new_message = Message(from_user=username, time=timestamp, message=message_content)
        db.session.add(new_message)
        db.session.commit()
        
        # Emit message to clients
        emit("receive_message", {
            "from": username,
            "time": timestamp,
            "message": message_content
        }, broadcast=True)

    
    
@socketio.on("get_messages")
def handle_get_messages():
    """
    List of all messages for a client.
    """
    all_messages = Message.query.all()  # Retrieve all messages from the database
    message_data = [
        {"from": msg.from_user, "time": msg.time, "message": msg.message} 
        for msg in all_messages
    ]
    emit("previous_messages", {"messages": message_data})




if __name__ == "__main__":
    # with app.app_context():
    #     db.create_all()

    socketio.run(app, debug=True)
