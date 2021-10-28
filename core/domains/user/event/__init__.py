from flask import g
from pubsub import pub

from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.enum import UserTopicEnum
from core.domains.user.repository.user_repository import UserRepository


def create_user(dto: CreateUserDto) -> None:
    UserRepository().create_user(dto=dto)
    setattr(g, UserTopicEnum.CREATE_USER, None)


def get_user_by_create_user_dto(dto: CreateUserDto) -> None:
    user = UserRepository().get_user_by_create_user_dto(dto=dto)
    setattr(g, UserTopicEnum.GET_USER, user)


def is_exists_user(provider_id: str, provider: str) -> None:
    user = UserRepository().is_exists_user(provider_id=provider_id, provider=provider)
    setattr(g, UserTopicEnum.IS_EXISTS_USER, user)


def is_exists_user_by_user_id(user_id: int) -> None:
    user = UserRepository().is_exists_user_by_user_id(user_id=user_id)
    setattr(g, UserTopicEnum.IS_EXISTS_USER_BY_USER_ID, user)


def update_user_uuid(dto: CreateUserDto) -> None:
    UserRepository().update_user_uuid(dto=dto)
    setattr(g, UserTopicEnum.UPDATE_USER_UUID, None)


def set_user_uuid_to_cache(user_id: int, uuid: str) -> None:
    # set to redis
    result = UserRepository().set_user_uuid_to_cache(user_id=user_id, uuid=uuid)
    setattr(g, UserTopicEnum.SET_USER_UUID_TO_CACHE, result)


def is_valid_user_uuid(uuid: str, user_id: int) -> None:
    result = UserRepository().is_valid_user_uuid(uuid=uuid, user_id=user_id)
    setattr(g, UserTopicEnum.IS_VALID_USER_UUID, result)


def is_valid_user_uuid_from_redis(uuid: str, user_id: int) -> None:
    result = UserRepository().is_valid_user_uuid_from_redis(uuid=uuid, user_id=user_id)
    setattr(g, UserTopicEnum.IS_VALID_USER_UUID_FROM_REDIS, result)


def update_current_connection_time(user_id: int) -> None:
    UserRepository().update_current_connection_time(user_id=user_id)
    setattr(g, UserTopicEnum.UPDATE_CURRENT_CONNECTION_TIME, None)


pub.subscribe(create_user, UserTopicEnum.CREATE_USER)
pub.subscribe(get_user_by_create_user_dto, UserTopicEnum.GET_USER)
pub.subscribe(is_exists_user, UserTopicEnum.IS_EXISTS_USER)
pub.subscribe(is_exists_user_by_user_id, UserTopicEnum.IS_EXISTS_USER_BY_USER_ID)
pub.subscribe(update_user_uuid, UserTopicEnum.UPDATE_USER_UUID)
pub.subscribe(set_user_uuid_to_cache, UserTopicEnum.SET_USER_UUID_TO_CACHE)
pub.subscribe(is_valid_user_uuid, UserTopicEnum.IS_VALID_USER_UUID)
pub.subscribe(
    is_valid_user_uuid_from_redis, UserTopicEnum.IS_VALID_USER_UUID_FROM_REDIS
)
pub.subscribe(
    update_current_connection_time, UserTopicEnum.UPDATE_CURRENT_CONNECTION_TIME
)
