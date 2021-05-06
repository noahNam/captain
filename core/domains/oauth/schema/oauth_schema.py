from pydantic import BaseModel, validator, ValidationError, StrictStr, StrictInt


class GetProviderSchema(BaseModel):
    provider: StrictStr = None

    @validator("provider")
    def provider_match(cls, value):
        if value is None or value.lower() not in ("kakao", "naver"):
            raise ValidationError("value must be equal to provider name")


class GetProviderIdSchema(BaseModel):
    provider_id: StrictInt = None


class ResponseOAuthSchema(BaseModel):
    pass
