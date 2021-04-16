from flask import g
from pubsub import pub

from core.domains.board.enum import PostTopicEnum
from core.domains.board.repository.board_repository import BoardRepository


def get_posts(user_id: int):
    posts = BoardRepository().get_posts(user_id=user_id)

    setattr(g, PostTopicEnum.GET_POSTS, posts)


pub.subscribe(get_posts, PostTopicEnum.GET_POSTS)
