from typing import Optional, Union

import inject

from app.extensions.utils.event_observer import send_message, get_event_object
from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.entity.user_entity import UserEntity
from core.domains.user.enum import UserTopicEnum
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class MakeTokenWithUserUseCase:
    # @inject.autoparams()
    # def __init__(self, auth_repo: AuthenticationRepository):
    #     self.__auth_repo = auth_repo

    def execute(self, dto: CreateUserDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self.__create_user(dto=dto)

        if not user:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)
        # JWT 발급

        return UseCaseSuccessOutput(value=user)

    def __create_user(self, dto: CreateUserDto) -> Optional[UserEntity]:
        send_message(topic_name=UserTopicEnum.CREATE_USER, dto=dto)

        return get_event_object(topic_name=UserTopicEnum.CREATE_USER)
