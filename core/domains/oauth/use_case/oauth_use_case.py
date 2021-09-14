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
        1. DB -> UserModel에 사용자가 존재한다 -> 로그인 -> UUID만 갱신한다 (update_user_uuid())
        2. DB -> UserModel에 등록된 사용자가 없다 -> 신규가입 (create_user())
        <공통 로직: 로그인 후 토큰과 UUID 캐싱처리>
        return JWT
    """

    def execute(
            self, dto: CreateUserDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        is_exists_user = self.__is_exists_user(
            provider_id=dto.provider_id, provider=dto.provider
        )

        if is_exists_user:
            self.__update_user_uuid(dto=dto)
        else:
            self.__create_user(dto=dto)
        user = self.__get_user_by_create_user_dto(dto=dto)

        if not user:
            return UseCaseFailureOutput(
                message="user id", detail=FailureType.NOT_FOUND_ERROR
            )

        # JWT 발급 + DB 저장
        get_user_dto = GetUserDto(user_id=user.id)
        is_jwt_exists = self.__is_exists_token(dto=get_user_dto)
        if is_jwt_exists:
            self.__update_token(dto=get_user_dto)
        else:
            self.__create_token(dto=get_user_dto)

        token_info = self.__get_token_info(dto=get_user_dto)

        if not token_info:
            return UseCaseFailureOutput(
                message="token_info", detail=FailureType.NOT_FOUND_ERROR
            )

        # Set UUID, token_info to redis
        if self.__is_redis_ready():
            self.__set_user_uuid_to_cache(user_id=user.id, uuid=dto.uuid)
            self.__set_token_to_cache(token_info=token_info)

        access_token = token_info.access_token

        result = jsonify(access_token=access_token)

        return UseCaseSuccessOutput(value=result)

    def __create_user(self, dto: CreateUserDto) -> None:
        send_message(topic_name=UserTopicEnum.CREATE_USER, dto=dto)
        return get_event_object(topic_name=UserTopicEnum.CREATE_USER)

    def __get_user_by_create_user_dto(self, dto: CreateUserDto) -> Optional[UserEntity]:
        send_message(topic_name=UserTopicEnum.GET_USER, dto=dto)
        return get_event_object(topic_name=UserTopicEnum.GET_USER)

    def __is_exists_token(self, dto: GetUserDto) -> bool:
        send_message(topic_name=AuthenticationTopicEnum.IS_EXISTS_TOKEN, dto=dto)
        return get_event_object(topic_name=AuthenticationTopicEnum.IS_EXISTS_TOKEN)

    def __update_token(self, dto: GetUserDto) -> None:
        send_message(topic_name=AuthenticationTopicEnum.UPDATE_TOKEN, dto=dto)
        return get_event_object(topic_name=AuthenticationTopicEnum.UPDATE_TOKEN)

    def __create_token(self, dto: GetUserDto) -> None:
        send_message(topic_name=AuthenticationTopicEnum.CREATE_TOKEN, dto=dto)
        return get_event_object(topic_name=AuthenticationTopicEnum.CREATE_TOKEN)

    def __get_token_info(self, dto: GetUserDto) -> Optional[JwtEntity]:
        send_message(topic_name=AuthenticationTopicEnum.GET_TOKEN_INFO, dto=dto)
        return get_event_object(topic_name=AuthenticationTopicEnum.GET_TOKEN_INFO)

    def __is_exists_user(self, provider_id: str, provider: str) -> bool:
        send_message(
            topic_name=UserTopicEnum.IS_EXISTS_USER,
            provider_id=provider_id,
            provider=provider,
        )

        return get_event_object(topic_name=UserTopicEnum.IS_EXISTS_USER)

    def __update_user_uuid(self, dto: CreateUserDto) -> None:
        send_message(topic_name=UserTopicEnum.UPDATE_USER_UUID, dto=dto)

        return get_event_object(topic_name=UserTopicEnum.UPDATE_USER_UUID)

    def __is_redis_ready(self) -> bool:
        send_message(topic_name=AuthenticationTopicEnum.IS_REDIS_READY)
        return get_event_object(topic_name=AuthenticationTopicEnum.IS_REDIS_READY)

    def __set_user_uuid_to_cache(self, user_id: int, uuid: str) -> bool:
        send_message(
            topic_name=UserTopicEnum.SET_USER_UUID_TO_CACHE, user_id=user_id, uuid=uuid
        )
        return get_event_object(topic_name=UserTopicEnum.SET_USER_UUID_TO_CACHE)

    def __set_token_to_cache(self, token_info: Optional[JwtEntity]) -> bool:
        send_message(
            topic_name=AuthenticationTopicEnum.SET_TOKEN_TO_CACHE, token_info=token_info
        )
        return get_event_object(topic_name=AuthenticationTopicEnum.SET_TOKEN_TO_CACHE)
