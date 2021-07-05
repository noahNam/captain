from datetime import datetime, timedelta


def get_server_timestamp() -> datetime:
    return datetime.now()


def get_jwt_access_expired_time_delta() -> timedelta:
    return timedelta(minutes=30)


def get_jwt_access_expire_timedelta_to_seconds() -> int:
    return int(timedelta(minutes=30).total_seconds())


def get_jwt_access_expire_timedelta_to_seconds_for_test() -> int:
    return int(timedelta(minutes=2).total_seconds())


def get_jwt_refresh_expired_time_delta() -> timedelta:
    return timedelta(days=14)


def get_jwt_refresh_expire_timedelta_to_seconds() -> int:
    return int(timedelta(days=14).total_seconds())


def get_jwt_access_expired_timestamp() -> datetime:
    return get_server_timestamp() + timedelta(minutes=30)


def get_jwt_refresh_expired_timestamp() -> datetime:
    return get_server_timestamp() + timedelta(days=14)
