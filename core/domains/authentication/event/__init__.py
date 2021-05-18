from flask import g
from pubsub import pub

from core.domains.authentication.enum import AuthenticationTopicEnum
from core.domains.authentication.repository.authentication_repository import AuthenticationRepository
from core.domains.user.dto.user_dto import CreateUserDto


def create_token(dto: CreateUserDto):
    token_info = AuthenticationRepository().create_token(dto=dto)
    # token_info = AuthenticationRepository().set_token_to_cache(dto=dto)
    setattr(g, AuthenticationTopicEnum.CREATE_TOKEN, token_info)


pub.subscribe(create_token, AuthenticationTopicEnum.CREATE_TOKEN)
