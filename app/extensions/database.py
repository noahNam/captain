from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session


db = SQLAlchemy()
migrate = Migrate()
session: Session = db.session
