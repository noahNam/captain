from pydantic import BaseModel, ValidationError

from core.domains.user.dto.user_dto import GetUserDto


class GetUserSchema(BaseModel):
    user_id: int


class GetUserRequest:
    def __init__(self, user_id):
        self.user_id = user_id

    def validate_request_and_make_dto(self):
        try:
            GetUserSchema(user_id=self.user_id)
            return self.to_dto()
        except ValidationError as e:
            print(e)
            return False

    def to_dto(self) -> GetUserDto:
        return GetUserDto(user_id=self.user_id)
