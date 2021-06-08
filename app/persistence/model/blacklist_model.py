from sqlalchemy import (
    Column,
    BigInteger,
    Integer,
    String,
    DateTime,
    ForeignKey,
)

from app import db
from app.persistence.model.user_model import UserModel
from app.extensions.utils.time_helper import get_jwt_access_expired_timestamp
from core.domains.authentication.entity.blacklist_entity import BlacklistEntity


class BlacklistModel(db.Model):
    __tablename__ = "blacklists"

    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )
    user_id = Column(BigInteger, ForeignKey(UserModel.id), nullable=False)
    access_token = Column(String(270), nullable=False)
    expired_at = Column(DateTime, nullable=False, default=get_jwt_access_expired_timestamp())

    def __repr__(self):
        return f"Blacklists('{self.id}', "\
               f"'{self.user_id}', " \
               f"'{self.access_token}', "\
               f"'{self.expired_at}'" \


    def to_entity(self) -> BlacklistEntity:
        return BlacklistEntity(
            id=self.id,
            user_id=self.user_id,
            access_token=self.access_token,
            expired_at=self.expired_at,
        )
