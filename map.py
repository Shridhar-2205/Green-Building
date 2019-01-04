from flask_admin import BaseView, expose
from flask_sqlalchemy import SQLAlchemy
from flask_security import current_user
from flask import Blueprint, current_app,render_template, session,abort,current_app

MapView = Blueprint('MapView',__name__, template_folder='templates')

