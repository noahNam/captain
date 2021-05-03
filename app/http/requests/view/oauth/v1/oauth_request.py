from pydantic import ValidationError

from core.domains.oauth.dto.oauth_dto import GetOAuthDto
from core.domains.oauth.schema.oauth_schema import GetOAuthSchema


class GetOAuthRequest:
    def __init__(self, provider: str):
        self.provider = provider

    def validate_request_and_make_dto(self):
        try:
            GetOAuthSchema(provider=self.provider)
            return self.to_dto()
        except ValidationError as e:
            print(e)
            return False

    def to_dto(self) -> GetOAuthDto:
        return GetOAuthDto(provider=self.provider)
