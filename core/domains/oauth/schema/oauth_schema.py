from pydantic import BaseModel, validator, ValidationError


class GetProviderSchema(BaseModel):
    provider: str = None

    @validator("provider")
    def provider_match(cls, value):
        if value is None or value.lower() not in ("kakao", "naver"):
            raise ValidationError('value must be equal to provider name')


class ResponseOAuthSchema(BaseModel):
    pass
