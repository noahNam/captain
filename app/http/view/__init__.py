from flask import Blueprint

api: Blueprint = Blueprint("api", __name__, url_prefix="/api/captain")

from .authentication.v1.auth_view import *  # noqa isort:skip
from .oauth.v1.oauth_view import *  # noqa isort:skip
