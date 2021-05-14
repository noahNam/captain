from pydantic import ValidationError, BaseModel, StrictStr, StrictInt, validator
from app.extensions.utils.log_helper import logger_
from app.http.responses import failure_response
from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto
from core.domains.oauth.enum.oauth_enum import ProviderEnum
from core.domains.user.dto.user_dto import CreateUserDto
from core.exception import InvalidRequestException
from core.use_case_output import UseCaseFailureOutput, FailureType

logger = logger_.getLogger(__name__)


class GetProviderSchema(BaseModel):
    provider: StrictStr = None

    @validator("provider")
    def provider_match(cls, provider):
        provider_list = [provider.value for provider in list(ProviderEnum)]
        if provider is None or provider.lower() not in provider_list:
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
            raise InvalidRequestException(message=e.errors())


class CreateUserRequest:
    def __init__(self, provider: str, provider_id: int):
        self.provider = provider
        self.provider_id = provider_id

    def validate_request_and_make_dto(self):
        try:
            schema = GetProviderSchema(provider=self.provider).dict()
            provider_id_schema = GetProviderIdSchema(provider_id=self.provider_id).dict()
            schema.update(provider_id_schema)

            # CreateUserDto : in User domain
            return CreateUserDto(**schema)
        except ValidationError as e:
            logger.error(
                f"[CreateUserRequest][validate_request_and_make_dto] error : {e}"
            )
            raise InvalidRequestException(
                message="provider_id must be int, or not receive id from Third_party server")
