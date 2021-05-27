from flask_jwt_extended import decode_token
from flask_jwt_extended.exceptions import JWTDecodeError
from jwt import PyJWTError
from pydantic import BaseModel, ValidationError, validator, StrictBytes

from core.domains.authentication.dto.authentication_dto import UpdateJwtDto
from app.extensions.utils.log_helper import logger_
from core.exception import InvalidRequestException

logger = logger_.getLogger(__name__)


class GetJwtSchema(BaseModel):
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

        except PyJWTError as e:
            logger.error(
                f"[UpdateTokenRequest][validate_request_and_make_dto][check_token] PyJWTError : {e}"
            )
            raise ValidationError(f"[UpdateTokenRequest][check_token] PyJWTError")
        except JWTDecodeError as e:
            logger.error(
                f"[UpdateTokenRequest][validate_request_and_make_dto][check_token] JWTDecodeError : {e}"
            )
            raise ValidationError(f"[UpdateTokenRequest][check_token] JWTDecodeError")
        return token


class UpdateTokenRequest:
    def __init__(self, token):
        self.token = token

    def validate_request_and_make_dto(self):
        try:
            schema = GetJwtSchema(token=self.token).dict()
            return UpdateJwtDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[UpdateTokenRequest][validate_request_and_make_dto] error : {e.errors()}"
            )
            raise InvalidRequestException(
                message=f"Invalid token")
