from typing import Union

import inject

from core.domains.user.dto.user_dto import GetUserDto, GetUserProviderDto
from core.domains.user.repository.user_repository import UserRepository
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class UserBaseUseCase:
    @inject.autoparams()
    def __init__(self, user_repo: UserRepository):
        self._user_repo = user_repo


class GetUserUseCase(UserBaseUseCase):
    def execute(
        self, dto: GetUserDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self._user_repo.get_user_by_user_id(user_id=dto.user_id)
        if not user:
            return UseCaseFailureOutput(detail=FailureType.NOT_FOUND_ERROR)
        return UseCaseSuccessOutput(value=user)


class GetUserProviderUseCase(UserBaseUseCase):
    def execute(
        self, dto: GetUserProviderDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        if not dto.user_id:
            return UseCaseFailureOutput(detail=FailureType.NOT_FOUND_ERROR)

        user_provider: str = self._user_repo.get_user_provider(dto=dto)

        return UseCaseSuccessOutput(value=user_provider)
