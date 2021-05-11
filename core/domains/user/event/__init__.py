from flask import g
from pubsub import pub

from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.enum import UserTopicEnum
from core.domains.user.repository.user_repository import UserRepository


def create_user(dto: CreateUserDto):
    UserRepository().create_user(dto=dto)
    user = UserRepository.get_user_by_create_user_dto(dto=dto)
    setattr(g, UserTopicEnum.CREATE_USER, user)


pub.subscribe(create_user, UserTopicEnum.CREATE_USER)
