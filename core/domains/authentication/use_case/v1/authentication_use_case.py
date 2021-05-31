from typing import Union, Optional

import inject
from flask import jsonify
from flask_jwt_extended import decode_token
from flask_jwt_extended.exceptions import JWTDecodeError

from app.extensions.utils.event_observer import send_message, get_event_object
from app.extensions.utils.time_helper import get_server_timestamp, get_jwt_now_timestamp_to_seconds
from core.domains.authentication.dto.authentication_dto import JwtDto, GetBlacklistDto

from core.domains.authentication.entity.blacklist_entity import BlacklistEntity
from core.domains.authentication.entity.jwt_entity import JwtEntity
from core.domains.authentication.enum import AuthenticationTopicEnum
from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.user.dto.user_dto import GetUserDto
from core.domains.user.entity.user_entity import UserEntity
from core.domains.user.enum import UserTopicEnum
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class UpdateJwtUseCase:
    def execute(self, dto: JwtDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        try:
            decoded = decode_token(dto.token, allow_expired=True)
        except JWTDecodeError as e:
            return UseCaseFailureOutput(
                message=f"Invalid Token, error: {e}", type=FailureType.INVALID_REQUEST_ERROR
            )

        user_id = decoded.get("identity")
        token_type = decoded.get("type")

        if not user_id:
            return UseCaseFailureOutput(
                message="user id is empty", type=FailureType.NOT_FOUND_ERROR
            )

        if token_type != ("access" or "refresh"):
            return UseCaseFailureOutput(
                message="wrong token type, need access or refresh", type=FailureType.INVALID_REQUEST_ERROR
            )
        user = self.__is_exists_user(user_id=user_id)

        if not user:
            return UseCaseFailureOutput(
                message="user not exists", type=FailureType.NOT_FOUND_ERROR
            )
        # JWT 토큰 업데이트
        # 위에서 사용자 존재 여부를 확인했기 때문에, 항상 토큰 업데이트
        token_info = self.__create_or_update_token(dto=GetUserDto(user_id=user_id))

        if not token_info:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)

        access_token = token_info.access_token

        result = jsonify(access_token=access_token)

        return UseCaseSuccessOutput(value=result)

    def __is_exists_user(self, user_id: int) -> Optional[UserEntity]:
        send_message(topic_name=UserTopicEnum.IS_EXISTS, user_id=user_id)

        return get_event_object(topic_name=UserTopicEnum.IS_EXISTS)

    def __create_or_update_token(self, dto: GetUserDto) -> Optional[JwtEntity]:
        send_message(topic_name=AuthenticationTopicEnum.CREATE_OR_UPDATE_TOKEN, dto=dto)

        return get_event_object(topic_name=AuthenticationTopicEnum.CREATE_OR_UPDATE_TOKEN)


class LogoutUseCase:
    def execute(self, dto: GetBlacklistDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        blacklist = self.__create_blacklist(dto=dto)

        if not blacklist:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)

        result = jsonify(logout_user=blacklist.user_id,
                         blacklist_token=blacklist.access_token.decode("utf-8"),
                         expired_at=blacklist.expired_at)

        return UseCaseSuccessOutput(value=result)

    def __create_blacklist(self, dto: GetBlacklistDto) -> Optional[BlacklistEntity]:
        send_message(topic_name=AuthenticationTopicEnum.CREATE_BLACKLIST, dto=dto)

        return get_event_object(topic_name=AuthenticationTopicEnum.CREATE_BLACKLIST)


class VerificationJwtUseCase:
    @inject.autoparams()
    def __init__(self, auth_repo: AuthenticationRepository):
        self._auth_repo = auth_repo

    def execute(self, dto: JwtDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        try:
            decoded = decode_token(dto.token, allow_expired=True)
        except JWTDecodeError as e:
            return UseCaseFailureOutput(
                message=f"Invalid Token, error: {e}", type=FailureType.INVALID_REQUEST_ERROR
            )

        user_id = int(decoded.get("identity"))
        token_type = decoded.get("type")

        if not user_id:
            return UseCaseFailureOutput(
                message="user id is empty", type=FailureType.NOT_FOUND_ERROR
            )

        if token_type != "access":
            return UseCaseFailureOutput(
                message="wrong token type, need access token", type=FailureType.INVALID_REQUEST_ERROR
            )

        # Blacklist check
        blacklist_dto = GetBlacklistDto(user_id=user_id, access_token=dto.token)

        if self._auth_repo.is_redis_ready():
            is_blacklist = self._auth_repo.is_blacklist_from_redis(dto=blacklist_dto)
        else:
            # from DB
            is_blacklist = self._auth_repo.get_blacklist_by_dto(dto=blacklist_dto)

        if is_blacklist:
            return UseCaseFailureOutput(
                message=f"Blacklist Token detected, please retry login", type=FailureType.UNAUTHORIZED_ERROR
            )

        # Valid access_token check
        if self._auth_repo.is_valid_access_token(dto=dto):
            result = jsonify(access_token=dto.token.decode("utf-8"))
            return UseCaseSuccessOutput(value=result)

        # Expired access_token from this line
        # Valid refresh_token check
        if self._auth_repo.is_redis_ready():
            # if refresh_token valid from redis
            if self._auth_repo.is_valid_refresh_token_from_redis(user_id=user_id):
                # update token
                self._auth_repo.create_or_update_token(dto=GetUserDto(user_id=user_id))
                new_token_info = self._auth_repo.get_token_info_by_user_id(user_id=user_id)
                # update to redis
                self._auth_repo.set_token_to_cache(token_info=new_token_info)
                result = jsonify(access_token=new_token_info.access_token)
                return UseCaseSuccessOutput(value=result)
            return UseCaseFailureOutput(
                message=f"Refresh Token expired, please retry login", type=FailureType.UNAUTHORIZED_ERROR
            )
        else:
            # redis 연결이 안될 경우 DB 에서 토큰 가져옴
            token_info = self._auth_repo.get_token_info_by_user_id(user_id=user_id)
            if token_info.refresh_expired_at < get_server_timestamp():
                return UseCaseFailureOutput(
                    message=f"Refresh Token expired, please retry login", type=FailureType.UNAUTHORIZED_ERROR
                )
            # DB 만 토큰 업데이트
            self._auth_repo.create_or_update_token(dto=GetUserDto(user_id=user_id))
            new_token_info = self._auth_repo.get_token_info_by_user_id(user_id=user_id)
            result = jsonify(access_token=new_token_info.access_token)
            return UseCaseSuccessOutput(value=result)
