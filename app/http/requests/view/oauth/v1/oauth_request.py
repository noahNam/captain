from pydantic import ValidationError, BaseModel, StrictStr, StrictInt, validator
from sqlalchemy import and_

from app.extensions.database import session
from app.extensions.utils.log_helper import logger_
from app.persistence.model.user_model import UserModel
from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto
from core.domains.user.dto.user_dto import CreateUserDto
from core.exception import InvalidRequestException

logger = logger_.getLogger(__name__)


class GetProviderSchema(BaseModel):
    provider: StrictStr = None

    @validator("provider")
    def provider_match(cls, provider):
        if provider is None or provider.lower() not in ("kakao", "naver"):
            raise ValidationError("value must be equal to provider name")
        return provider


class GetProviderIdSchema(BaseModel):
    provider_id: StrictInt = None


class GetOAuthRequest:
    def __init__(self, provider: str):
        self.provider = provider

    def validate_request_and_make_dto(self):
        try:
            schema = GetProviderSchema(provider=self.provider).dict()
            return GetOAuthProviderDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[GetOAuthRequest][validate_request_and_make_dto] error : {e}"
            )
            raise InvalidRequestException(message="Invalid provider value")


class CreateUserRequest:
    def __init__(self, provider: str, provider_id: int):
        self.provider = provider
        self.provider_id = provider_id

    def validate_request_and_make_dto(self):
        try:
            schema = GetProviderSchema(provider=self.provider).dict()
            provider_id_schema = GetProviderIdSchema(provider_id=self.provider_id).dict()
            schema.update(provider_id_schema)

            # 유저가 존재하면 바로 JWT Blacklist 검증
            # if session.query(
            #         exists().where(UserModel.provider == dto.provider) \
            #                 .where(UserModel.provider_id == dto.provider_id)) \
            #         .scalar():

            # CreateUserDto : in User domain
            return CreateUserDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[CreateUserRequest][validate_request_and_make_dto] error : {e}"
            )
            raise InvalidRequestException(
                message="provider_id must be int, or not receive id from Third_party server")
