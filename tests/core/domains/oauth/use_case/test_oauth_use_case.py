from typing import List
from uuid import uuid4

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import scoped_session

from app.persistence.model import UserModel
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.oauth.use_case.oauth_use_case import CreateTokenWithUserUseCase
from core.domains.user.dto.user_dto import CreateUserDto
from core.use_case_output import UseCaseSuccessOutput

uuid_v4 = str(uuid4())


def test_create_token_when_create_user_by_pypubsub_then_success(
        session: scoped_session,
):
    dto = CreateUserDto(provider=ProviderEnum.KAKAO.value, provider_id=12345, uuid=uuid_v4)

    result = CreateTokenWithUserUseCase().execute(dto=dto)

    assert result.type == "success"
    assert isinstance(result, UseCaseSuccessOutput)
    assert b"access_token" in result.value.data


def test_create_token_when_exists_user_by_pypubsub_then_update_only_uuid(
        session: scoped_session,
        db: SQLAlchemy,
        create_users: List[UserModel]
):
    before_uuid = create_users[0].uuid
    dto = CreateUserDto(provider=create_users[0].provider,
                        provider_id=create_users[0].provider_id,
                        uuid=uuid_v4)

    result = CreateTokenWithUserUseCase().execute(dto=dto)

    # create new session
    connection = db.engine.connect()
    options = dict(bind=connection, binds={})

    session_2 = db.create_scoped_session(options=options)
    after_user = session.query(UserModel).filter_by(provider=dto.provider,
                                                    provider_id=dto.provider_id).first()
    users = session_2.query(UserModel).filter_by(id=after_user.id).all()

    assert result.type == "success"
    assert isinstance(result, UseCaseSuccessOutput)
    assert b"access_token" in result.value.data
    assert len(users) == 1

    assert before_uuid != users[0].uuid
    assert users[0].uuid == dto.uuid
    assert users[0].provider == dto.provider
    assert users[0].provider_id == dto.provider_id

    # session 2 remove
    session_2.remove()
