from flask import render_template, request, redirect, make_response, send_from_directory
from functools import wraps
from datetime import datetime, timezone, timedelta
import jwt
import config as conf
import db as db_config
from app import app
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

CONST_LOGIN = "login.html"
CONST_WAIT = "wait.html"
CONST_LIST = "list.html"

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            return redirect("/")
        try:
            data = jwt.decode(token, conf.secret_key, algorithms=["HS256"])
            return f(data=data, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return "Session expired!", 403
        except jwt.InvalidTokenError:
            return "Invalid token!", 403

    return decorated_function


@app.route("/")
def home():
    form = LoginForm()
    return render_template(CONST_LOGIN, form=form)


@app.route("/waiting", methods=["GET"])
@jwt_required
def waiting_GET(data):
    return render_template(
        CONST_WAIT, user=data["user"], group=data["group"]
    )


@app.route("/waiting", methods=["POST"])
@jwt_required
def waiting_POST(data):
    ALLOWED_FILES = ["flag/flag.txt", "message.txt"]
    file = request.form.get("file")
    try:
        # Use a secure method to read file contents
        with open(f"message.txt", 'r') as f:
            command = f.read()

        if file not in ALLOWED_FILES:
            return render_template(
                CONST_WAIT,
                command="Stay in scope you sneaky you ;)",
                user=data["user"],
                group=data["group"]
            )

        return render_template(
            CONST_WAIT,
            command=command,
            user=data["user"],
            group=data["group"]
        )
    except SystemExit as e:
        return render_template(
            CONST_WAIT,
            command=f"An error occurred while reading the file: {e}",
            user=data["user"],
            group=data["group"]
        )


@app.route('/image/<image_name>')
def serve_image(image_name):
    return send_from_directory('images', image_name)


@app.route("/register", methods=["GET"])
def register_GET():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register_POST():
    try:
        db_config.add_user(
            request.form.get("username"),
            request.form.get("password"),
            request.form.get("role"),
        )
    except Exception as e:
        print(f"Could not add the user:\n{e}")
        return render_template("register.html")
    form = LoginForm()
    return render_template(CONST_LOGIN, msg="User created! Please log in.", form=form)



# The POST request for getting the username and password.
@app.route("/login", methods=["POST"])
def login():
    form = LoginForm()
    # Get the information from the user.
    username = request.form.get("username")
    password = request.form.get("password")
    db_users = conf.Users.query.order_by(conf.Users.userId).all()

    for user in db_users:
        if username in user.username and password == user.password:
            # If the username and password is correct, generate JWT with the secret key.
            timestamp = datetime.now(timezone.utc).timestamp()
            token = jwt.encode(
                {
                    "user": username,
                    "group": user.user_group,
                    "exp": datetime.fromtimestamp(timestamp, timezone.utc) + timedelta(minutes=60),
                },
                conf.secret_key,
                algorithm="HS256",
            )
            if user.user_group == "guest":
                resp = make_response(redirect("/waiting"))
            else:
                resp = make_response(redirect("/list"))
            resp.set_cookie("token", token, httponly=True, secure=True)
            return resp
    # return render_template(CONST_LOGIN, error_msg="Invalid credentials", form=form)


@app.route("/list", methods=["GET"])
@jwt_required
def index_GET(data):
    tasks = conf.Todo.query.order_by(conf.Todo.date_created).all()
    return render_template(
        CONST_LIST, tasks=tasks, user=data["user"], group=data["group"]
    )


@app.route("/list", methods=["POST"])
@jwt_required
def index_POST(data):
    new_task = conf.Todo(content=request.form["content"], user=data["user"])
    try:
        conf.db.session.add(new_task)
        conf.db.session.commit()
        return redirect("/list")
    except Exception as e:
        return f"An error occurred while creating the task: {str(e)}"


@app.route("/manage_users", methods=["GET"])
@jwt_required
def manage_users(data):
    if data["group"] == "dev":
        users = conf.Users.query.order_by(conf.Users.userId).all()
        return render_template(
            "manage_users.html", user=data["user"], group=data["group"], users=users
        )


@app.route("/delete/<int:id>")
@jwt_required
def delete(id, data):
    try:
        conf.db.session.delete(conf.Todo.query.get_or_404(id))
        conf.db.session.commit()
        tasks = conf.Todo.query.order_by(conf.Todo.date_created).all()
        return render_template(
            CONST_LIST, tasks=tasks, user=data["user"], group=data["group"]
        )
    except Exception as e:
        return f"An error occurred while deleting the task: {str(e)}"


@app.route("/update/<int:id>", methods=["GET"])
@jwt_required
def update_GET(id, data):
    task = conf.Todo.query.get_or_404(id)
    # Check if the logged-in user owns the task
    if task.user != data["user"]:
        return render_template(
            "update.html", task=task, user=data["user"], group=data["group"]
        )

@app.route("/update/<int:id>", methods=["POST"])
@jwt_required
def update_POST(id, data):
    task = conf.Todo.query.get_or_404(id)
    if task.user != data["user"]:
        return render_template(
            "update.html", task=task, user=data["user"], group=data["group"]
        )
    task.content = request.form["content"]

    try:
        conf.db.session.commit()
        tasks = conf.Todo.query.order_by(conf.Todo.date_created).all()
        return render_template(
            CONST_LIST, tasks=tasks, user=data["user"], group=data["group"]
        )
    except Exception as e:
        return f"An error occurred while updating the task: {str(e)}"


# Only users in the "admin" group can access this resource.
@app.route("/admin")
@jwt_required
def admin(data):
    if data["group"] == "admin":
        users = conf.Users.query.order_by(conf.Users.userId).all()
        return render_template(
            "admin.html", user=data["user"], group=data["group"], users=users
        )
    else:
        tasks = conf.Todo.query.order_by(conf.Todo.date_created).all()
        return render_template(
            CONST_LIST, tasks=tasks, user=data["user"], group=data["group"]
        )


# A secret place only logged-in users can visit. (To test authentication).
@app.route("/secret")
@jwt_required
def secret(data):
    if data["group"] == "admin" or data["group"] == "user":
        return render_template(
            "secret.html", user=data["user"], group=data["group"]
        )
    else:
        return make_response(redirect("/"))


# A logout button that clears the cookie.
@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("token", "", expires=0, httponly=True, secure=True)
    return resp