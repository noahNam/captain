from flask_jwt_extended import decode_token
from pydantic import BaseModel, ValidationError, validator, StrictBytes, StrictInt
from pydantic.types import UUID4

from core.domains.authentication.dto.authentication_dto import (
    JwtDto,
    GetBlacklistDto,
    JwtWithUUIDDto,
)
from app.extensions.utils.log_helper import logger_
from core.exception import InvalidRequestException

logger = logger_.getLogger(__name__)


class GetJwtAllowedExpiredSchema(BaseModel):
    token: StrictBytes

    @validator("token")
    def check_token(cls, token):
        """
            decode_token() : 정상적인 JWT 라면 decode 가능
            -> allow_expired=True : 만료된 토큰도 decode 허용
            -> 토큰이 올바른 구조인지 체크
        """
        try:
            decode_token(token, allow_expired=True)

        except Exception as e:
            logger.error(f"[GetJwtAllowedExpiredSchema][check_token] Error : {e}")
            raise ValidationError(f"[GetJwtAllowedExpiredSchema][check_token] Error")

        return token


class GetUUIDv4Schema(BaseModel):
    uuid: UUID4 = None


class AllowedExpiredJwtTokenRequest:
    def __init__(self, token: bytes):
        self.token = token

    def validate_request_and_make_dto(self):
        try:
            schema = GetJwtAllowedExpiredSchema(token=self.token).dict()
            return JwtDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[AllowedExpiredJwtTokenRequest][validate_request_and_make_dto] error : {e}"
            )
            raise InvalidRequestException(message=e.errors())


class AllowedExpiredJwtTokenWithUUIDRequest:
    def __init__(self, token: bytes, uuid: str):
        self.token = token
        self.uuid = uuid

    def validate_request_and_make_dto(self):
        try:
            schema = GetJwtAllowedExpiredSchema(token=self.token).dict()
            uuid_schema = GetUUIDv4Schema(uuid=UUID4(self.uuid)).dict()
            uuid_schema["uuid"] = str(uuid_schema.get("uuid"))
            schema.update(uuid_schema)
            return JwtWithUUIDDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[AllowedExpiredJwtTokenWithUUIDRequest][validate_request_and_make_dto] error : {e}"
            )
            raise InvalidRequestException(message=e.errors())


class GetBlacklistSchema(BaseModel):
    access_token: str
    user_id: StrictInt

    @validator("access_token")
    def check_access_token(cls, access_token):
        """
            allow_expired=False : 만료된 토큰 허용 안함
        """
        try:
            decode_token(access_token.encode("utf-8"))

        except Exception as e:
            logger.error(f"[GetBlacklistSchema][check_access_token] Error : {e}")
            raise ValidationError(f"[GetBlacklistSchema][check_access_token] error")

        return access_token


class LogoutRequest:
    def __init__(self, access_token, user_id):
        self.access_token = access_token
        self.user_id = user_id

    def validate_request_and_make_dto(self):
        try:
            schema = GetBlacklistSchema(
                access_token=self.access_token, user_id=self.user_id
            ).dict()
            return GetBlacklistDto(**schema)
        except ValidationError as e:
            logger.error(f"[LogoutRequest][validate_request_and_make_dto] error : {e}")
            raise InvalidRequestException(message=e.errors())
