from sqlalchemy import Column, BigInteger, Integer, String, DateTime
from sqlalchemy.orm import relationship, backref

from app import db
from app.extensions.utils.time_helper import get_server_timestamp
from core.domains.user.entity.user_entity import UserEntity


class UserModel(db.Model):
    __tablename__ = "users"

    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )
    provider = Column(String(10), nullable=False)
    provider_id = Column(BigInteger(), nullable=False)
    group = Column(String(10), nullable=True)
    created_at = Column(DateTime, default=get_server_timestamp())
    updated_at = Column(DateTime, default=get_server_timestamp())

    jwt_models = relationship("JwtModel", backref=backref("jwts"))

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
