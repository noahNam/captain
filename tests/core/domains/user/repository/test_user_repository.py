from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import scoped_session

from app.persistence.model.user_model import UserModel
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.repository.user_repository import UserRepository

kakao_user_dto = CreateUserDto(
    provider=ProviderEnum.KAKAO.value,
    provider_id=12345
)
provider_list = tuple([provider.value for provider in list(ProviderEnum)])


def test_create_user_when_get_provider_id(session: scoped_session):
    UserRepository().create_user(dto=kakao_user_dto)
    user = session.query(UserModel).first()

    assert user.provider == kakao_user_dto.provider
    assert user.provider_id == kakao_user_dto.provider_id


def test_create_user_with_duplicate_provider_with_provider_id_then_pass_create_user(
        session: scoped_session):
    UserRepository().create_user(dto=kakao_user_dto)
    UserRepository().create_user(dto=kakao_user_dto)
    count = session.query(UserModel).count()

    assert count == 1


def test_create_user_without_required_value_then_validation_error(
        session: scoped_session):
    with pytest.raises(ValidationError):
        dummy_dto = CreateUserDto(
            provider=ProviderEnum.KAKAO.value,
        )
        UserRepository().create_user(dto=dummy_dto)


def test_create_user_when_use_create_users_fixture_then_make_two_users(
        session: scoped_session, create_users: Any):
    users = session.query(UserModel).all()

    assert len(users) == 2
    for i in range(2):
        assert users[i].provider in provider_list
        assert type(users[i].provider_id) == int


def test_get_user_with_factory_boy(session: scoped_session, create_users: Any):
    for entry in create_users:
        user = session.query(UserModel).get(dict(id=entry.id))
        assert entry.to_entity() == user.to_entity()


def test_compare_create_user_when_use_build_batch_and_create_users_fixture(
        session: scoped_session, create_users: Any, user_factory):
    fixture_users = session.query(UserModel).all()
    build_batch_users = user_factory.build_batch(size=3, provider=ProviderEnum.KAKAO.value)

    assert len(fixture_users) == 2
    assert len(build_batch_users) == 3
    assert fixture_users[0].id != build_batch_users[0].id
