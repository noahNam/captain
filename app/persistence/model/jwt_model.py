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
from app.extensions.utils.time_helper import (
    get_jwt_access_expired_timestamp,
    get_jwt_refresh_expired_timestamp,
)
from core.domains.authentication.entity.jwt_entity import JwtEntity


class JwtModel(db.Model):
    __tablename__ = "jwts"

    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )
    user_id = Column(BigInteger, ForeignKey(UserModel.id), nullable=False)
    access_token = Column(String(280), nullable=False)
    refresh_token = Column(String(280), nullable=False)
    access_expired_at = Column(
        DateTime, nullable=False, default=get_jwt_access_expired_timestamp()
    )
    refresh_expired_at = Column(
        DateTime, nullable=False, default=get_jwt_refresh_expired_timestamp()
    )

    def __repr__(self):
        return (
            f"Jwts('{self.id}', "
            f"'{self.user_id}', "
            f"'{self.access_token}', "
            f"'{self.refresh_token}', "
            f"'{self.access_expired_at}', "
            f"'{self.refresh_expired_at}')"
        )

    def to_entity(self) -> JwtEntity:
        return JwtEntity(
            id=self.id,
            user_id=self.user_id,
            access_token=self.access_token,
            refresh_token=self.refresh_token,
            access_expired_at=self.access_expired_at,
            refresh_expired_at=self.refresh_expired_at,
        )
