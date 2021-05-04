from datetime import datetime

from sqlalchemy import Column, BigInteger, Integer, String, DateTime

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
    provider = Column(String(10))
    provider_id = Column(BigInteger().with_variant(Integer, "sqlite"))
    group = Column(String(50), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.id}', " \
               f"'{self.provider}', " \
               f"'{self.provider_id}', " \
               f"'{self.group}', " \
               f"'{self.created_at}', " \
               f"'{self.updated_at}')"

    def to_entity(self) -> UserEntity:
        return UserEntity(
            id=self.id,
            provider=self.provider,
            provider_id=self.provider_id,
            group=self.group,
            created_at=self.created_at,
            updated_at=self.updated_at
        )
