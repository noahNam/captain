import inject

from core.domains.board.repository.board_repository import BoardRepository
from core.domains.user.repository.user_repository import UserRepository


def init_provider():
    inject.clear_and_configure(
        lambda binder: binder.bind_to_provider(UserRepository, UserRepository)
    )
    inject.clear_and_configure(
        lambda binder: binder.bind_to_provider(BoardRepository, BoardRepository)
    )
