import inject

from core.domains.user.repository.user_repository import UserRepository


def init_provider():
    inject.clear_and_configure(
        lambda binder: binder.bind_to_provider(UserRepository, UserRepository)
    )
