import pytest
from pydantic import ValidationError
from sqlalchemy.orm import scoped_session

from app.extensions import RedisClient
from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.user.dto.user_dto import GetUserDto
from tests.conftest import app

get_user_dto = GetUserDto(user_id=1)


def test_create_token_when_get_user_id(session: scoped_session):
    token_info = AuthenticationRepository().create_token(dto=get_user_dto)

    assert token_info.user_id == get_user_dto.user_id
    assert token_info.access_token is not None
    assert token_info.refresh_token is not None


def test_create_token_without_user_id_then_validation_error(
        session: scoped_session):
    with pytest.raises(ValidationError):
        dummy_dto = GetUserDto(user_id=None)
        AuthenticationRepository().create_token(dto=dummy_dto)


def test_redis_example():
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
