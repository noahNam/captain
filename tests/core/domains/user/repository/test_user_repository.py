from typing import Any, List
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import scoped_session

from app.persistence.model.user_model import UserModel
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.repository.user_repository import UserRepository

uuid_v4 = str(uuid4())
kakao_user_dto = CreateUserDto(provider=ProviderEnum.KAKAO.value, provider_id="12345", uuid=uuid_v4)
provider_list = tuple([provider.value for provider in list(ProviderEnum)])


def test_create_user_when_get_provider_id(session: scoped_session):
    """
        given : 신규사용자
        when : OAuth 로그인
        then : DB 저장
    """
    UserRepository().create_user(dto=kakao_user_dto)
    user = session.query(UserModel).first()

    assert user.provider == kakao_user_dto.provider
    assert user.provider_id == kakao_user_dto.provider_id
    assert user.uuid == kakao_user_dto.uuid


def test_update_user_uuid_when_user_login_then_update_uuid(
        session: scoped_session,
        create_users: List[UserModel]
):
    """
        given: 기존 사용자
        when: OAuth 로그인
        then: uuid 업데이트
    """
    dto = CreateUserDto(provider=create_users[0].provider,
                        provider_id=create_users[0].provider_id,
                        uuid=uuid_v4)
    UserRepository().update_user_uuid(dto=dto)

    assert create_users[0].provider == dto.provider
    assert create_users[0].provider_id == dto.provider_id
    assert create_users[0].uuid != dto.uuid


def test_is_exists_user_when_user_in_db_then_return_true(
        session: scoped_session,
        create_users: List[UserModel]
):
    """
        given: 기존 사용자의 provider, provider_id
        when: 사용자 여부 체크
        then: True
    """
    result = UserRepository().is_exists_user(provider=create_users[0].provider,
                                             provider_id=create_users[0].provider_id)
    assert result is True


def test_create_user_without_required_value_then_validation_error(
        session: scoped_session,
):
    """
        given: 적절하지 않은 CreateUserDto
        when: create_user()
        then: validation error
    """
    with pytest.raises(ValidationError):
        dummy_dto = CreateUserDto(provider=ProviderEnum.KAKAO.value, )
        UserRepository().create_user(dto=dummy_dto)


def test_create_user_when_use_create_users_fixture_then_make_two_users(
        session: scoped_session,
        create_users: List[UserModel]
):
    """
        create_users fixture test
    """
    users = session.query(UserModel).all()

    assert len(users) == 2
    for i in range(2):
        assert users[i].provider in provider_list
        assert type(users[i].provider_id) == str


def test_get_user_with_factory_boy(session: scoped_session, create_users: List[UserModel]):
    """
        factory_boy instance test
    """
    for entry in create_users:
        user = session.query(UserModel).get(dict(id=entry.id))
        assert entry.to_entity() == user.to_entity()


def test_compare_create_user_when_use_build_batch_and_create_users_fixture(
        session: scoped_session, create_users: Any, user_factory
):
    """
        factory_boy build_batch test
    """
    fixture_users = session.query(UserModel).all()
    build_batch_users = user_factory.build_batch(
        size=3, provider=ProviderEnum.KAKAO.value
    )

    assert len(fixture_users) == 2
    assert len(build_batch_users) == 3
    assert fixture_users[0].id != build_batch_users[0].id
