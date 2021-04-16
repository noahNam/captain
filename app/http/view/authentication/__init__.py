from functools import wraps
from http import HTTPStatus

from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from werkzeug.local import LocalProxy

from core.use_case_output import FailureType


def _get_user_id():
    user_id = get_jwt_identity()

    return int(user_id) if user_id else None


user_id = LocalProxy(_get_user_id)


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not user_id:
            return (
                jsonify({"type": FailureType.UNAUTHORIZED_ERROR, "message": ""}),
                HTTPStatus.UNAUTHORIZED,
            )

        return fn(*args, **kwargs)

    return wrapper
