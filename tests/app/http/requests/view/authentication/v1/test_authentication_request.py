from uuid import uuid4

import pytest
from flask_jwt_extended import create_access_token, create_refresh_token

from app.extensions.utils.time_helper import (
    get_jwt_access_expired_time_delta,
    get_jwt_refresh_expired_time_delta,
)
from app.http.requests.view.authentication.authentication_request import (
    AllowedExpiredJwtTokenRequest,
    LogoutRequest, AllowedExpiredJwtTokenWithUUIDRequest,
)
from core.exception import InvalidRequestException
from tests.seeder.conftest import make_random_today_date
from tests.seeder.factory import make_custom_jwt

uuid_v4 = str(uuid4())


def create_invalid_access_token(user_id):
    """
        어제 날짜로 만료된 토큰 (access)
    """
    yesterday = make_random_today_date(1, 0)
    return make_custom_jwt(
        obj=user_id,
        token_type="access",
        now=yesterday,
        delta=get_jwt_access_expired_time_delta(),
    )


def create_invalid_refresh_token(user_id):
    """
        2주 지나서 만료된 토큰 (refresh)
    """
    more_then_two_weeks_ago = make_random_today_date(15, 0)
    return make_custom_jwt(
        obj=user_id,
        token_type="refresh",
        now=more_then_two_weeks_ago,
        delta=get_jwt_refresh_expired_time_delta(),
    )


def test_update_token_request_when_get_valid_access_token_then_success(
        create_base_users,
):
    """
        유효한 토큰 -> 성공 (access)
    """
    token = create_access_token(identity=create_base_users[0].id)
    token_to_byte = token.encode("utf-8")
    result = AllowedExpiredJwtTokenRequest(
        token=token_to_byte,
    ).validate_request_and_make_dto()

    assert result.token == token_to_byte

def test_verification_request_when_get_valid_access_token_and_uuid_then_success(
        create_base_users,
):
    """
        유효한 토큰, uuid -> 성공 (access)
    """
    token = create_access_token(identity=create_base_users[0].id)
    token_to_byte = token.encode("utf-8")
    result = AllowedExpiredJwtTokenWithUUIDRequest(
        token=token_to_byte,
        uuid=uuid_v4
    ).validate_request_and_make_dto()

    assert result.token == token_to_byte
    assert result.uuid == uuid_v4


def test_update_token_request_when_get_expired_access_token_then_success(
        create_base_users,
):
    """
        Update_token : 만료된 토큰 허용
        만료된 토큰도 요청 성공 (access)
    """
    token = create_invalid_access_token(user_id=create_base_users[0].id)
    result = AllowedExpiredJwtTokenRequest(token=token).validate_request_and_make_dto()
    assert result.token == token


def test_verification_request_when_get_expired_access_token_and_uuid_then_success(
        create_base_users,
):
    """
        Update_token : 만료된 토큰 허용
        uuid : uuid_v4
        만료된 토큰도 요청 성공 (access)
    """
    token = create_invalid_access_token(user_id=create_base_users[0].id)
    result = AllowedExpiredJwtTokenWithUUIDRequest(token=token, uuid=uuid_v4).validate_request_and_make_dto()
    assert result.token == token
    assert result.uuid == uuid_v4


def test_update_token_request_when_get_invalid_token_then_failure(create_base_users):
    """
        아예 규격이 맞지 않은 토큰일 경우 실패
    """
    token = b"Wrong access token"
    with pytest.raises(InvalidRequestException):
        AllowedExpiredJwtTokenRequest(token=token).validate_request_and_make_dto()


def test_verification_request_when_get_invalid_token_then_failure(create_base_users):
    """
        아예 규격이 맞지 않은 토큰일 경우 실패
    """
    token = b"Wrong access token"
    with pytest.raises(InvalidRequestException):
        AllowedExpiredJwtTokenWithUUIDRequest(token=token, uuid=uuid_v4).validate_request_and_make_dto()


def test_update_token_request_when_get_valid_refresh_token_then_success(
        create_base_users,
):
    """
        유효한 토큰 -> 성공 (refresh)
    """
    token = create_refresh_token(identity=create_base_users[0].id)
    token_to_byte = token.encode("utf-8")
    result = AllowedExpiredJwtTokenRequest(
        token=token_to_byte,
    ).validate_request_and_make_dto()
    assert result.token == token_to_byte


def test_verification_request_when_get_valid_refresh_token_with_uuid_then_success(
        create_base_users,
):
    """
        유효한 토큰 -> 성공 (refresh)
    """
    token = create_refresh_token(identity=create_base_users[0].id)
    token_to_byte = token.encode("utf-8")
    result = AllowedExpiredJwtTokenWithUUIDRequest(
        token=token_to_byte,
        uuid=uuid_v4
    ).validate_request_and_make_dto()
    assert result.token == token_to_byte
    assert result.uuid == uuid_v4


def test_update_token_request_when_get_expired_refresh_token_then_success(
        create_base_users,
):
    """
        만료된 토큰도 요청 성공 (refresh)
    """
    token = create_invalid_refresh_token(user_id=create_base_users[0].id)
    result = AllowedExpiredJwtTokenRequest(token=token).validate_request_and_make_dto()
    assert result.token == token


def test_verification_request_when_get_expired_refresh_token_with_uuid_then_success(
        create_base_users,
):
    """
        만료된 토큰도 요청 성공 (refresh)
    """
    token = create_invalid_refresh_token(user_id=create_base_users[0].id)
    result = AllowedExpiredJwtTokenWithUUIDRequest(token=token, uuid=uuid_v4).validate_request_and_make_dto()
    assert result.token == token
    assert result.uuid == uuid_v4


# Logout Request Test
def test_logout_request_when_get_valid_access_token_then_success(create_base_users):
    """
        유효한 토큰 -> 성공 (access)
    """
    user_id = create_base_users[0].id
    token = create_access_token(identity=user_id)
    token_to_byte = token.encode("utf-8")
    result = LogoutRequest(
        access_token=token_to_byte, user_id=user_id
    ).validate_request_and_make_dto()

    assert result.access_token.encode("utf-8") == token_to_byte


def test_logout_token_request_when_get_expired_access_token_then_failure(
        create_base_users,
):
    """
        logout_token : 만료된 토큰 허용 X
    """
    user_id = create_base_users[0].id
    token = create_invalid_access_token(user_id=user_id)
    with pytest.raises(InvalidRequestException):
        LogoutRequest(
            access_token=token, user_id=user_id
        ).validate_request_and_make_dto()


def test_logout_request_when_get_invalid_token_then_failure(create_base_users):
    """
        아예 규격이 맞지 않은 토큰일 경우 실패
    """
    user_id = create_base_users[0].id
    token = b"Wrong access token"
    with pytest.raises(InvalidRequestException):
        LogoutRequest(
            access_token=token, user_id=user_id
        ).validate_request_and_make_dto()
