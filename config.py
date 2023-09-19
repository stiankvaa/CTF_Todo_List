from flask import Flask
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///list.db'
db = SQLAlchemy(app)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Integer, default=0)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(100))

    def __repr__(self):
        return f"<Task {self.id} | Content: {self.content} | Created at: {self.date_created}>"


class Users(db.Model):
    userId = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_group = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<User {self.userId} | Username: {self.username} | Group: {self.user_group}>"



# username:password
users = {
    "pål": "hr_ansatt1",
    "morten": "it_ansatt3",
    "flag_bærer_john": "54s6e5cdrf9872bgex8712gex97y3diu32hd3o487o3",
    "admin": "admin123",
    "<script>alert(\'ahh..\')</script>": "password",
    "TheBoss":"0321498r7nxy34871ryyufhfgu"
}
# username:group
groups = {
    "pål": "user",
    "morten": "user",
    "flag_bærer_john": "user",
    "admin": "admin",
    "<script>alert(\'ahh..\')</script>":"user",
    "TheBoss":"user"
}

#
secret_key = "secret123"
