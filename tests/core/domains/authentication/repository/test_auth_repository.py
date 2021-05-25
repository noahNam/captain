import jwt
import pytest
from flask_jwt_extended import decode_token
from pydantic import ValidationError
from sqlalchemy.orm import scoped_session

from app.extensions import RedisClient
from app.extensions.utils.time_helper import get_jwt_access_expired_time_delta, get_jwt_refresh_expired_time_delta
from app.persistence.model import UserModel, BlacklistModel
from app.persistence.model.jwt_model import JwtModel
from core.domains.authentication.dto.authentication_dto import GetBlacklistDto
from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.user.dto.user_dto import GetUserDto, CreateUserDto
from core.domains.user.repository.user_repository import UserRepository
from tests.seeder.conftest import make_random_today_date
from tests.seeder.factory import make_custom_jwt

get_user_dto = GetUserDto(user_id=10)


def test_create_token_when_get_user_id(session: scoped_session):
    """
        given : User DTO (user_id)
        when : 로그인 로직 -> 신규 유저 생성 시점
        then : 토큰 생성 및 DB 저장
    """
    AuthenticationRepository().create_or_update_token(dto=get_user_dto)
    token_info = session.query(JwtModel).filter_by(user_id=get_user_dto.user_id).first()

    assert token_info.user_id == get_user_dto.user_id
    assert token_info.access_token is not None
    assert token_info.refresh_token is not None


def test_create_token_without_user_id_then_validation_error(
        session: scoped_session):
    """
        given : user_id = None
        when : 로그인 로직 -> 신규 유저 생성 시점
        then : DTO Validation Error
    """
    with pytest.raises(ValidationError):
        dummy_dto = GetUserDto(user_id=None)
        AuthenticationRepository().create_or_update_token(dto=dummy_dto)


def test_update_token_when_get_user_id(session: scoped_session, create_invalid_jwts):
    dto = GetUserDto(user_id=create_invalid_jwts[0].user_id)
    token_before = session.query(JwtModel).filter_by(user_id=dto.user_id).first()

    AuthenticationRepository().create_or_update_token(dto=dto)
    token_after = session.query(JwtModel).filter_by(user_id=dto.user_id).first()

    t = decode_token(token_after.access_token)
    print(t)

    assert token_before.user_id == dto.user_id

    assert token_before.user_id == token_after.user_id
    assert token_before.id == token_after.id

    # 업데이트된 토큰 == 새로운 토큰 + 만료시간 갱신(기존 토큰과 값이 달라야 함)
    assert token_before.access_token != token_after.access_token
    assert token_before.refresh_token != token_after.refresh_token
    assert token_before.access_expired_at != token_after.access_expired_at
    assert token_before.refresh_expired_at != token_after.refresh_expired_at


def test_redis_example(app):
    redis_url = "redis://localhost:6379"
    test_redis = RedisClient()
    test_redis.init_app(app=app, url=redis_url)

    # Set redis
    key = "user_id:1"
    message = 'token-asdfasdfasdfasdfasdf'
    test_redis.set(
        key=key,
        value=message,
        ex=600,
    )

    # searching key via pattern -> class key 변수 set
    test_redis.scan_pattern(pattern="user_id*")

    # pattern에 해당하는 모든 키 값을 가져와야 할 때 -> class key 변수로 처리
    result = dict()
    while True:
        try:
            data = test_redis.get_after_scan()
            if data is None:
                break
            result[data["key"].decode().split(":")[1]] = data["value"]
        except Exception as e:
            print("get_after_scan exception")
            break

    # 하나의 key 값만 가져올 때
    value = test_redis.get_by_key(key=key)

    # Clear cache
    if test_redis.copied_keys:
        print(f"[*] Clear keys -> {test_redis.copied_keys}")
        test_redis.clear_cache()

    assert value.decode('ascii') == message
    assert key.split(":")[1] == "1"
    assert result[key.split(":")[1]].decode('ascii') == message


def test_set_token_to_redis_when_get_token_info(
        session: scoped_session, redis: RedisClient, create_users: list):
    """
        given : 신규 JWT
        when : 로그인 로직 -> 신규 유저 생성 + 신규 JWT 생성된 시점
        then : Redis에 토큰 정보 저장

        <key> : <value>
            jwt_access_token : user_id
            user_id : jwt_refresh_token
    """
    token_info = session.query(JwtModel).filter_by(user_id=create_users[0].id).first()
    result = AuthenticationRepository().set_token_to_cache(token_info)

    value_user_id = redis.get_by_key(key=token_info.access_token)
    value_refresh_token = redis.get_by_key(key=token_info.user_id)

    assert result is True
    assert value_user_id == b'1'
    assert value_refresh_token == token_info.refresh_token


def test_verify_token_when_get_valid_token_then_decode_success(
        session: scoped_session):
    """
        given : JWT
        when : Valid Datetime
        then : Success decode
    """
    AuthenticationRepository().create_or_update_token(dto=get_user_dto)
    token_info = session.query(JwtModel).filter_by(user_id=get_user_dto.user_id).first()

    decoded_access = decode_token(token_info.access_token)
    decoded_refresh = decode_token(token_info.refresh_token)
    assert decoded_access.get("identity") == get_user_dto.user_id
    assert decoded_access.get("type") == "access"
    assert decoded_refresh.get("identity") == get_user_dto.user_id
    assert decoded_refresh.get("type") == "refresh"


def test_verify_access_token_when_get_invalid_token_then_decode_fail(
        session: scoped_session):
    """
        given : JWT (access_token)
        when : Invalid Datetime
        then : Fail decode
    """
    yesterday = make_random_today_date(1, 0)

    invalid_access_token = make_custom_jwt(get_user_dto.user_id,
                                           now=yesterday,
                                           token_type="access",
                                           delta=get_jwt_access_expired_time_delta())

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(invalid_access_token)


def test_verify_refresh_token_when_get_invalid_token_then_decode_fail(
        session: scoped_session):
    """
        given : JWT (refresh_token)
        when : Invalid Datetime
        then : Fail decode
    """
    more_then_two_weeks_ago = make_random_today_date(15, 0)

    invalid_refresh_token = make_custom_jwt(get_user_dto.user_id,
                                            now=more_then_two_weeks_ago,
                                            token_type="refresh",
                                            delta=get_jwt_refresh_expired_time_delta())

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(invalid_refresh_token)


def test_create_blacklist_when_blacklist_id(session: scoped_session,
                                            create_users: list):
    """
        given : Blacklist DTO (user_id, access_token)
        when : 유저 로그 아웃
        then : Blacklist 생성 및 DB 저장
    """
    token_info = session.query(JwtModel).filter_by(user_id=create_users[0].id).first()

    blacklist_dto = GetBlacklistDto(user_id=create_users[0].id,
                                    access_token=token_info.access_token)

    AuthenticationRepository().create_blacklist(dto=blacklist_dto)

    blacklist = session.query(BlacklistModel).filter_by(user_id=create_users[0].id).first()

    assert blacklist.user_id == create_users[0].id
    assert blacklist.access_token is not None


def test_delete_blacklist_when_blacklist_id(session: scoped_session,
                                            create_users: list):
    """
        given : Blacklist DTO (user_id, access_token)
        when : 별도 배치 정리 작업(주기적으로 삭제)
        then : Blacklist DB 제거
    """
    token_info = session.query(JwtModel).filter_by(user_id=create_users[0].id).first()

    blacklist_dto = GetBlacklistDto(user_id=create_users[0].id,
                                    access_token=token_info.access_token)

    AuthenticationRepository().create_blacklist(dto=blacklist_dto)

    AuthenticationRepository().delete_blacklist(dto=blacklist_dto)

    blacklist = session.query(BlacklistModel).filter_by(user_id=create_users[0].id).first()

    assert blacklist.user_id == create_users[0].id
    assert blacklist.access_token is not None
