import pytest
from pydantic import ValidationError
from sqlalchemy.orm import scoped_session

from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.user.dto.user_dto import GetUserDto

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
