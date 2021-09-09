from pydantic import ValidationError, BaseModel, StrictStr, validator
from pydantic.types import UUID4

from app.extensions.utils.log_helper import logger_
from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.user.dto.user_dto import CreateUserDto
from core.exception import InvalidRequestException

logger = logger_.getLogger(__name__)


class GetProviderSchema(BaseModel):
    provider: StrictStr = None

    @validator("provider")
    def provider_match(cls, provider):
        provider_list = tuple([provider.value for provider in list(ProviderEnum)])
        if provider is None or provider.lower() not in provider_list:
            raise ValidationError("value must be equal to provider name")
        return provider


class GetProviderIdSchema(BaseModel):
    provider_id: StrictStr = None

    @validator("provider_id")
    def provider_id_match(cls, provider_id):
        if not provider_id or provider_id == "None":
            raise ValidationError("no provider id")
        return provider_id


class GetUUIDv4Schema(BaseModel):
    uuid: UUID4 = None


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
            raise InvalidRequestException(message=e.errors())


class CreateUserRequest:
    def __init__(self, provider: str, provider_id: str, uuid: str):
        self.provider = provider
        self.provider_id = provider_id
        self.uuid = uuid

    def validate_request_and_make_dto(self):
        try:
            schema = GetProviderSchema(provider=self.provider).dict()
            provider_id_schema = GetProviderIdSchema(
                provider_id=self.provider_id
            ).dict()
            uuid_schema = GetUUIDv4Schema(uuid=UUID4(self.uuid)).dict()
            uuid_schema["uuid"] = str(uuid_schema.get("uuid"))
            schema.update(provider_id_schema)
            schema.update(uuid_schema)

            # CreateUserDto : in User domain
            return CreateUserDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[CreateUserRequest][validate_request_and_make_dto] error : {e}"
            )
            raise InvalidRequestException(
                message="provider_id must be str, or not receive id from Third_party server"
            )
