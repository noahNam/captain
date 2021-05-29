from typing import List

from flask_jwt_extended import create_access_token
from sqlalchemy.orm import scoped_session

from app.extensions import RedisClient
from core.domains.authentication.dto.authentication_dto import UpdateJwtDto, GetBlacklistDto
from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.authentication.use_case.v1.authentication_use_case import UpdateJwtUseCase, LogoutUseCase
from core.use_case_output import FailureType, UseCaseSuccessOutput
from tests.app.http.requests.view.authentication.v1.test_authentication_request import create_invalid_access_token
from tests.seeder.factory import InvalidJwtFactory, make_custom_jwt, UserBaseFactory


def test_update_token_when_get_expired_token(
        session: scoped_session, redis: RedisClient,
        create_base_users: List[UserBaseFactory]):
    """
        given : 만료된 JWT access_token, 기존 사용자
        when : update token request from tanos
        then : success
    """
    user_id = create_base_users[0].id

    token = create_invalid_access_token(user_id=user_id)
    dto = UpdateJwtDto(token=token)

    result = UpdateJwtUseCase().execute(dto=dto)
    updated_token_info = AuthenticationRepository().get_token_info_by_user_id(user_id=user_id)
    value_user_id = redis.get_by_key(key=updated_token_info.access_token)
    value_refresh_token = redis.get_by_key(key=user_id)

    assert result.type == "success"
    assert isinstance(result, UseCaseSuccessOutput)
    assert b"access_token" in result.value.data
    # 업데이트 전 후 토큰 비교
    assert token != updated_token_info.access_token.encode("utf-8")
    # redis check
    assert int(value_user_id.decode("utf-8")) == user_id
    assert value_refresh_token.decode("utf-8") == updated_token_info.refresh_token


def test_update_token_when_get_expired_access_token_with_no_user_then_response_error(
        session: scoped_session, create_invalid_jwts: List[InvalidJwtFactory]):
    """
        given : 만료된 JWT access_token, 등록되지 않은 사용자
        when : update token request from tanos
        then : not found error
    """
    dto = UpdateJwtDto(token=create_invalid_jwts[0].access_token)

    result = UpdateJwtUseCase().execute(dto=dto)
    assert result.type == FailureType.NOT_FOUND_ERROR
    assert result.message == "user not exists"


def test_update_token_when_get_token_with_wrong_type_then_response_error(
        session: scoped_session, create_base_users: List[UserBaseFactory]):
    """
        given : access, refresh 외 type JWT
        when : update token request from tanos
        then : invalid request error
    """
    user_id = create_base_users[0].id
    token = make_custom_jwt(obj=user_id, token_type="wrong")
    dto = UpdateJwtDto(token=token)

    result = UpdateJwtUseCase().execute(dto=dto)
    assert result.type == FailureType.INVALID_REQUEST_ERROR


def test_logout_when_get_token_with_user_id_then_success(
        session: scoped_session, redis: RedisClient, create_base_users: List[UserBaseFactory]):
    """
        given : access_token, user_id
        when : logout request
        then : success
    """
    user_id = create_base_users[0].id
    token = create_access_token(identity=user_id)
    token_to_byte = token.encode("utf-8")

    dto = GetBlacklistDto(user_id=user_id, access_token=token_to_byte)
    result = LogoutUseCase().execute(dto=dto)

    assert result.type == "success"
    assert isinstance(result, UseCaseSuccessOutput)
    assert b"blacklist_token" in result.value.data
    assert b"expired_at" in result.value.data

    blacklists_in_redis = redis.smembers("jwt_blacklist")

    # redis check
    assert redis.sismember(set_name="jwt_blacklist", value=token_to_byte) is True
    assert token_to_byte in blacklists_in_redis
