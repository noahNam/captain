from sqlalchemy import Column, BigInteger, Integer, String

from app import db
from core.domains.user.entity.user_entity import UserEntity


class UserModel(db.Model):
    __tablename__ = "users"

    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )
    nickname = Column(String(45), nullable=False)

    def to_entity(self) -> UserEntity:
        return UserEntity(id=self.id, nickname=self.nickname)
