from sqlalchemy import Column, BigInteger, Integer, String, DateTime, func, SmallInteger
from sqlalchemy.orm import relationship, backref

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
    uuid = Column(String(36), nullable=False)
    provider = Column(String(10), nullable=False)
    provider_id = Column(String(256), nullable=False)
    group = Column(SmallInteger(), nullable=True)
    current_connection_time = Column(
        DateTime(), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    created_at = Column(DateTime(), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    jwt_models = relationship("JwtModel", backref=backref("jwts"))
    blacklists_models = relationship("BlacklistModel", backref=backref("blacklists"))

    def __repr__(self):
        return (
            f"User('{self.id}', "
            f"'{self.uuid}', "
            f"'{self.provider}', "
            f"'{self.provider_id}', "
            f"'{self.group}', "
            f"'{self.current_connection_time}', "
            f"'{self.created_at}', "
            f"'{self.updated_at}')"
        )

    def to_entity(self) -> UserEntity:
        return UserEntity(
            id=self.id,
            uuid=self.uuid,
            provider=self.provider,
            provider_id=self.provider_id,
            group=self.group,
            current_connection_time=self.current_connection_time,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
