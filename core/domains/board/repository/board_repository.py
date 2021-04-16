from typing import List

from app.extensions.database import session
from app.persistence.model.post_model import PostModel
from core.domains.board.entity.post_entity import PostEntity


class BoardRepository:
    def get_posts(self, user_id: int) -> List[PostEntity]:
        posts = session.query(PostModel).filter_by(user_id=user_id).all()

        return [post.to_entity() for post in posts]
