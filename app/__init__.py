from flask import Flask
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Set secret key first
csrf = CSRFProtect()
csrf.init_app(app)


from app import routes
