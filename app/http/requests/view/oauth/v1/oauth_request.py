from pydantic import ValidationError

from core.domains.oauth.dto.oauth_dto import GetOAuthProviderDto
from core.domains.oauth.schema.oauth_schema import GetProviderSchema


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
