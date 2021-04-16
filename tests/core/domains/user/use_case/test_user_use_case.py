from app.persistence.model.post_model import PostModel
from app.persistence.model.user_model import UserModel
from core.domains.user.dto.user_dto import GetUserDto
from core.domains.user.use_case.v1.user_use_case import (
    GetUserUseCase,
    GetUserWithPostUseCase,
)


def test_when_get_user_then_success(session):
    user = UserModel(nickname="Tester")

    session.add(user)
    session.commit()

    dto = GetUserDto(user_id=user.id)

    result = GetUserUseCase().execute(dto=dto)

    assert result.value == user.to_entity()


def test_when_get_user_with_post_by_pypubsub_success(session):
    user = UserModel(nickname="Tester")

    session.add(user)
    session.commit()

    post = PostModel(user_id=user.id, title="post title", body="post body")

    session.add(post)
    session.commit()

    dto = GetUserDto(user_id=user.id)

    result = GetUserWithPostUseCase().execute(dto=dto)

    user_entity = result.value
    posts_entity = user_entity.posts

    assert user_entity.id == user.id
    assert posts_entity[0].id == post.id


def test_when_check_post_existing_then_success(session):
    """
    단 시간에 여러 번 pypubsub listener 호출 후 누락되는 거 없는지 확인
    """
    user = UserModel(nickname="Tester")

    session.add(user)
    session.commit()

    post = PostModel(user_id=user.id, title="post title", body="post body")

    session.add(post)
    session.commit()

    dto = GetUserDto(user_id=user.id)

    for _ in range(700):
        result = GetUserWithPostUseCase().execute(dto=dto)

        user_entity = result.value
        posts_entity = user_entity.posts

        assert user_entity.id == user.id
        assert posts_entity[0].id == post.id
