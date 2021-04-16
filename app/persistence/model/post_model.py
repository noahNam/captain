from sqlalchemy import Column, BigInteger, Integer, String, DateTime, ForeignKey

from sqlalchemy.orm import relationship

from app import db
from app.extensions.utils.time_helper import get_server_timestamp
from core.domains.board.entity.post_entity import PostEntity


class PostModel(db.Model):
    __tablename__ = "posts"

    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )
    title = Column(String, default="")
    body = Column(String, default="")
    created_at = Column(DateTime, default=get_server_timestamp())
    updated_at = Column(DateTime, default=get_server_timestamp())
    user_id = Column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
    )

    user = relationship(
        "UserModel",
        primaryjoin="PostModel.user_id == UserModel.id",
        backref="post",
    )

    def to_entity(self) -> PostEntity:
        return PostEntity(
            id=self.id,
            user_id=self.user_id,
            title=self.title,
            body=self.body,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
