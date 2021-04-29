from flask import Blueprint

api: Blueprint = Blueprint("api/captain", __name__)

from .authentication.v1.auth_view import *  # noqa isort:skip
from .user.v1.user_view import *  # noqa isort:skip
