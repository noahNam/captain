from typing import Optional, Union

import inject
from flask import jsonify
from flask_jwt_extended import create_access_token, create_refresh_token

from app.extensions.utils.event_observer import send_message, get_event_object
from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.entity.user_entity import UserEntity
from core.domains.user.enum import UserTopicEnum
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class CreateTokenWithUserUseCase:
    """
        UserRepository->create_user
        return JWT
        todo : AuthenticationRepository->check_blacklist->store_token in auth branch
    """

    def execute(self, dto: CreateUserDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self.__create_user(dto=dto)

        if not user:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)

        # JWT 발급
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        token_info = jsonify(access_token=access_token, refresh_token=refresh_token)

        return UseCaseSuccessOutput(value=token_info)

    def __create_user(self, dto: CreateUserDto) -> Optional[UserEntity]:
        send_message(topic_name=UserTopicEnum.CREATE_USER, dto=dto)

        return get_event_object(topic_name=UserTopicEnum.CREATE_USER)
