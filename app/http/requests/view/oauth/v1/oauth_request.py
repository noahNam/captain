from pydantic import ValidationError

from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto, CreateUserDto
from core.domains.oauth.schema.oauth_schema import GetProviderSchema, GetProviderIdSchema


class GetOAuthRequest:
    def __init__(self, provider: str):
        self.provider = provider

    def validate_request_and_make_dto(self):
        try:
            GetProviderSchema(provider=self.provider)
            return self.to_dto()
        except ValidationError as e:
            print(e)
            return False

    def to_dto(self) -> GetOAuthProviderDto:
        return GetOAuthProviderDto(provider=self.provider)


class CreateUser:
    def __init__(self, provider: str, provider_id: int):
        self.provider = provider
        self.provider_id = provider_id

    def validate_request_and_make_dto(self):
        try:
            GetProviderSchema(provider=self.provider)
            GetProviderIdSchema(provider_id=self.provider_id)
            return self.to_dto()
        except ValidationError as e:
            print(e)
            return False

    def to_dto(self) -> CreateUserDto:
        return CreateUserDto(provider=self.provider, provider_id=self.provider_id)
