from sqlalchemy.orm import scoped_session

from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.oauth.use_case.oauth_use_case import CreateTokenWithUserUseCase
from core.domains.user.dto.user_dto import CreateUserDto
from core.use_case_output import UseCaseSuccessOutput


def test_create_token_when_create_user_by_pypubsub_then_success(
    session: scoped_session,
):
    dto = CreateUserDto(provider=ProviderEnum.KAKAO.value, provider_id=12345)

    result = CreateTokenWithUserUseCase().execute(dto=dto)

    assert result.type == "success"
    assert isinstance(result, UseCaseSuccessOutput)
    assert b"access_token" in result.value.data
