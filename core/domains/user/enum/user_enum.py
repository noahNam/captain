from enum import Enum


class ExtendedEnum(Enum):
    @classmethod
    def list(cls):
        return list(map(lambda c: c.value, cls))


class UserGroupEnum(Enum):
    """
        사용모델 : UserModel
    """

    ADMIN = 0
    USER = 1
