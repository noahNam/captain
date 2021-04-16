from typing import Union, List

import inject

from app.extensions.utils.event_observer import get_event_object, send_message
from core.domains.board.entity.post_entity import PostEntity
from core.domains.board.enum import PostTopicEnum
from core.domains.user.dto.user_dto import GetUserDto
from core.domains.user.repository.user_repository import UserRepository
from core.use_case_output import UseCaseSuccessOutput, UseCaseFailureOutput, FailureType


class GetUserUseCase:
    @inject.autoparams()
    def __init__(self, user_repo: UserRepository):
        self.__user_repo = user_repo

    def execute(
        self, dto: GetUserDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self.__user_repo.get_user(user_id=dto.user_id)
        if not user:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)
        return UseCaseSuccessOutput(value=user)


class GetUserWithPostUseCase:
    @inject.autoparams()
    def __init__(self, user_repo: UserRepository):
        self.__user_repo = user_repo

    def execute(
        self, dto: GetUserDto
    ) -> Union[UseCaseSuccessOutput, UseCaseFailureOutput]:
        user = self.__user_repo.get_user(user_id=dto.user_id)
        posts = self.__get_posts(user_id=user.id)

        if not posts and not user:
            return UseCaseFailureOutput(type=FailureType.NOT_FOUND_ERROR)

        user.posts = posts
        return UseCaseSuccessOutput(value=user)

    def __get_posts(self, user_id: int) -> List[PostEntity]:
        send_message(topic_name=PostTopicEnum.GET_POSTS, user_id=user_id)

        return get_event_object(topic_name=PostTopicEnum.GET_POSTS)
