from flask import g
from pubsub import pub

from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.enum import UserTopicEnum
from core.domains.user.repository.user_repository import UserRepository


def create_user(dto: CreateUserDto) -> None:
    UserRepository().create_user(dto=dto)
    user = UserRepository().get_user_by_create_user_dto(dto=dto)
    setattr(g, UserTopicEnum.CREATE_USER, user)


def get_user(user_id: int) -> None:
    user = UserRepository().get_user_by_user_id(user_id=user_id)
    setattr(g, UserTopicEnum.GET_USER, user)


def is_exists_user(provider_id: str, provider: str) -> None:
    user = UserRepository().is_exists_user(provider_id=provider_id, provider=provider)
    setattr(g, UserTopicEnum.IS_EXISTS_USER, user)


def update_user_uuid(dto: CreateUserDto) -> None:
    UserRepository().update_user_uuid(dto=dto)
    user = UserRepository().get_user_by_create_user_dto(dto=dto)
    setattr(g, UserTopicEnum.UPDATE_USER_UUID, user)


pub.subscribe(create_user, UserTopicEnum.CREATE_USER)
pub.subscribe(get_user, UserTopicEnum.GET_USER)
pub.subscribe(is_exists_user, UserTopicEnum.IS_EXISTS_USER)
pub.subscribe(update_user_uuid, UserTopicEnum.UPDATE_USER_UUID)
