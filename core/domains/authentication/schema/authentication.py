from pydantic import BaseModel, StrictStr


class AuthenticationResponseSchema(BaseModel):
    type: StrictStr
