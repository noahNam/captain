from typing import Union, Optional

import inject
from flask import jsonify
from flask_jwt_extended import decode_token
from flask_jwt_extended.exceptions import JWTDecodeError

from app.extensions.utils.event_observer import send_message, get_event_object
from core.domains.authentication.dto.authentication_dto import (
    JwtDto,
    GetBlacklistDto,
    GetUserDto,
    JwtWithUUIDDto,
)
from core.domains.authentication.entity.blacklist_entity import BlacklistEntity
from core.domains.authentication.enum import AuthenticationTopicEnum
from core.domains.authentication.repository.authentication_repository import (
    AuthenticationRepository,
)
from core.domains.user.entity.user_entity import UserEntity
from core.domains.user.enum import UserTopicEnum
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class JwtBaseUseCase:
    @inject.autoparams()
    def __init__(self, auth_repo: AuthenticationRepository):
        self._auth_repo = auth_repo


class UpdateJwtUseCase(JwtBaseUseCase):
    def execute(self, dto: JwtDto) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        try:
            decoded = decode_token(dto.token, allow_expired=True)
        except JWTDecodeError as e:
            return UseCaseFailureOutput(
                message=f"Invalid Token, error: {e}",
                detail=FailureType.INVALID_REQUEST_ERROR,
            )
        try:
            user_id = int(decoded.get("identity"))
        except Exception:
            return UseCaseFailureOutput(
                message="user id", detail=FailureType.INVALID_REQUEST_ERROR
            )
        token_type = decoded.get("type")

        if not user_id or type(user_id) != int:
            return UseCaseFailureOutput(
                message="user id", detail=FailureType.NOT_FOUND_ERROR
            )

        if token_type != ("access" or "refresh"):
            return UseCaseFailureOutput(
                message="wrong token type, need access or refresh",
                detail=FailureType.INVALID_REQUEST_ERROR,
            )
        get_user_dto = GetUserDto(user_id=user_id)
        is_exists_token = self._auth_repo.is_exists_token(dto=get_user_dto)

        if not is_exists_token:
            return UseCaseFailureOutput(
                message="user object", detail=FailureType.NOT_FOUND_ERROR
            )
        # JWT 토큰 업데이트
        # 위에서 사용자 존재 여부를 확인했기 때문에, 항상 토큰 업데이트
        self._auth_repo.update_token(dto=get_user_dto)
        token_info = self._auth_repo.get_token_info_by_dto(dto=get_user_dto)

        if not token_info:
            return UseCaseFailureOutput(
                message="token_info", detail=FailureType.NOT_FOUND_ERROR
            )

        # update token to redis
        if self._auth_repo.is_redis_ready():
            self._auth_repo.set_token_to_cache(token_info=token_info)

        access_token = token_info.access_token

        result = jsonify(access_token=access_token)

        return UseCaseSuccessOutput(value=result)

    def __is_exists_user_by_user_id(self, user_id: int) -> bool:
        send_message(
            topic_name=UserTopicEnum.IS_EXISTS_USER_BY_USER_ID, user_id=user_id
        )
        return get_event_object(topic_name=UserTopicEnum.IS_EXISTS_USER_BY_USER_ID)


class LogoutUseCase:
    def execute(
        self, dto: GetBlacklistDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        blacklist = self.__create_blacklist(dto=dto)

        if not blacklist:
            return UseCaseFailureOutput(
                message="blacklist", detail=FailureType.INTERNAL_SERVER_ERROR
            )

        result = jsonify(
            logout_user=blacklist.user_id,
            blacklist_token=blacklist.access_token,
            expired_at=blacklist.expired_at,
        )

        return UseCaseSuccessOutput(value=result)

    def __create_blacklist(self, dto: GetBlacklistDto) -> Optional[BlacklistEntity]:
        send_message(topic_name=AuthenticationTopicEnum.CREATE_BLACKLIST, dto=dto)

        return get_event_object(topic_name=AuthenticationTopicEnum.CREATE_BLACKLIST)


class VerificationJwtUseCase(JwtBaseUseCase):
    def execute(
        self, dto: JwtWithUUIDDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        try:
            decoded = decode_token(dto.token, allow_expired=True)
        except JWTDecodeError as e:
            return UseCaseFailureOutput(
                message=f"Invalid Token, error: {e}",
                detail=FailureType.INVALID_REQUEST_ERROR,
            )

        user_id = int(decoded.get("identity"))
        token_type = decoded.get("type")

        if not user_id:
            return UseCaseFailureOutput(
                message="user id", detail=FailureType.NOT_FOUND_ERROR
            )

        if token_type != "access":
            return UseCaseFailureOutput(
                message="wrong token type, need access token",
                detail=FailureType.INVALID_REQUEST_ERROR,
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
                message=f"Blacklist Token detected, please retry login",
                detail=FailureType.UNAUTHORIZED_ERROR,
            )

        # Valid access_token check
        if self._auth_repo.is_valid_token(token=dto.token):
            result = jsonify(access_token=dto.token.decode("utf-8"))
            return UseCaseSuccessOutput(value=result)

        # Expired access_token from this line
        # Valid refresh_token check
        if self._auth_repo.is_redis_ready():
            # if refresh_token valid from redis
            if self._auth_repo.is_valid_refresh_token_from_redis(
                user_id=user_id
            ) and self.__is_valid_user_uuid_from_redis(uuid=dto.uuid, user_id=user_id):
                # update token
                self._auth_repo.update_token(dto=GetUserDto(user_id=user_id))
                new_token_info = self._auth_repo.get_token_info_by_user_id(
                    user_id=user_id
                )
                # update to redis
                self._auth_repo.set_token_to_cache(token_info=new_token_info)
                result = jsonify(access_token=new_token_info.access_token)
                return UseCaseSuccessOutput(value=result)

            return UseCaseFailureOutput(
                message=f"Refresh Token expired, please retry login",
                detail=FailureType.UNAUTHORIZED_ERROR,
            )
        else:
            # redis 연결이 안될 경우 DB 에서 토큰 가져옴
            if not (
                self._auth_repo.is_valid_refresh_token(user_id=user_id)
                and self.__is_valid_user_uuid(uuid=dto.uuid, user_id=user_id)
            ):
                return UseCaseFailureOutput(
                    message=f"Refresh Token expired, please retry login",
                    detail=FailureType.UNAUTHORIZED_ERROR,
                )
            # DB 만 토큰 업데이트
            self._auth_repo.update_token(dto=GetUserDto(user_id=user_id))
            new_token_info = self._auth_repo.get_token_info_by_user_id(user_id=user_id)

            result = jsonify(access_token=new_token_info.access_token)
            return UseCaseSuccessOutput(value=result)

    def __is_valid_user_uuid(self, uuid: str, user_id: int) -> bool:
        send_message(
            topic_name=UserTopicEnum.IS_VALID_USER_UUID, uuid=uuid, user_id=user_id
        )
        return get_event_object(topic_name=UserTopicEnum.IS_VALID_USER_UUID)

    def __is_valid_user_uuid_from_redis(self, uuid: str, user_id: int) -> bool:
        send_message(
            topic_name=UserTopicEnum.IS_VALID_USER_UUID_FROM_REDIS,
            uuid=uuid,
            user_id=user_id,
        )
        return get_event_object(topic_name=UserTopicEnum.IS_VALID_USER_UUID_FROM_REDIS)
