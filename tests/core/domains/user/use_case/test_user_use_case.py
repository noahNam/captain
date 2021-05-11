from app.persistence.model.user_model import UserModel
from core.domains.user.dto.user_dto import GetUserDto
from core.domains.user.use_case.v1.user_use_case import (
    GetUserUseCase,
)


def test_when_get_user_then_success(session):
    user = UserModel(provider="kakao", provider_id=12345)

    session.add(user)
    session.commit()

    dto = GetUserDto(user_id=user.id)

    result = GetUserUseCase().execute(dto=dto)

    assert result.value == user.to_entity()
