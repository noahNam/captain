from typing import Union

import inject

from core.domains.user.dto.user_dto import GetUserDto
from core.domains.user.repository.user_repository import UserRepository
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class GetUserUseCase:
    @inject.autoparams()
    def __init__(self, user_repo: UserRepository):
        self.__user_repo = user_repo

    def execute(
        self, dto: GetUserDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self.__user_repo.get_user_by_user_id(user_id=dto.user_id)
        if not user:
            return UseCaseFailureOutput(detail=FailureType.NOT_FOUND_ERROR)
        return UseCaseSuccessOutput(value=user)
