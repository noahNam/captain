import pytest
from pydantic import ValidationError
from sqlalchemy.orm import scoped_session

from app.extensions import RedisClient
from app.persistence.model.jwt_model import JwtModel
from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.user.dto.user_dto import GetUserDto

get_user_dto = GetUserDto(user_id=1)


def test_create_token_when_get_user_id(session: scoped_session):
    token_info = AuthenticationRepository().create_or_update_token(dto=get_user_dto)

    assert token_info.user_id == get_user_dto.user_id
    assert token_info.access_token is not None
    assert token_info.refresh_token is not None


def test_create_token_without_user_id_then_validation_error(
        session: scoped_session):
    with pytest.raises(ValidationError):
        dummy_dto = GetUserDto(user_id=None)
        AuthenticationRepository().create_or_update_token(dto=dummy_dto)


def test_update_token_when_get_user_id(session: scoped_session):
    token_before = AuthenticationRepository().create_or_update_token(dto=get_user_dto)
    AuthenticationRepository().create_or_update_token(dto=get_user_dto)

    token_after = session.query(JwtModel).filter_by(user_id=get_user_dto.user_id).first()

    assert token_before.user_id == get_user_dto.user_id
    assert token_before.user_id == token_after.user_id
    assert token_before.id == token_after.id
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
