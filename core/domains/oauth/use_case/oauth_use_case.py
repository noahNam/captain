from typing import Optional, Union
from flask import jsonify
from app.extensions.utils.event_observer import send_message, get_event_object
from core.domains.authentication.entity.jwt_entity import JwtEntity
from core.domains.authentication.enum import AuthenticationTopicEnum
from core.domains.user.dto.user_dto import CreateUserDto, GetUserDto
from core.domains.user.entity.user_entity import UserEntity
from core.domains.user.enum import UserTopicEnum
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class CreateTokenWithUserUseCase:
    """
        UserRepository
        -> 1. create (신규 로그인)
        -> 2. update if user exists (로그아웃 후 재로그인)
        return JWT
    """

    def execute(self, dto: CreateUserDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self.__create_user(dto=dto)

        if not user:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)

        # JWT 발급 + DB 저장
        user_dto = GetUserDto(user_id=user.id)

        token_info = self.__create_or_update_token(dto=user_dto)

        if not token_info:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)

        access_token = token_info.access_token

        result = jsonify(access_token=access_token)

        return UseCaseSuccessOutput(value=result)

    def __create_user(self, dto: CreateUserDto) -> Optional[UserEntity]:
        send_message(topic_name=UserTopicEnum.CREATE_USER, dto=dto)

        return get_event_object(topic_name=UserTopicEnum.CREATE_USER)

    def __create_or_update_token(self, dto: GetUserDto) -> Optional[JwtEntity]:
        send_message(topic_name=AuthenticationTopicEnum.CREATE_OR_UPDATE_TOKEN, dto=dto)

        return get_event_object(topic_name=AuthenticationTopicEnum.CREATE_OR_UPDATE_TOKEN)
