from datetime import datetime, timedelta

from flask import current_app


def get_server_timestamp():
    return datetime.now()


def get_jwt_access_expired_timestamp():
    return get_server_timestamp() + timedelta(minutes=30)


def get_jwt_refresh_expired_timestamp():
    return get_server_timestamp() + timedelta(days=14)
