from app.persistence.model.user_model import UserModel
from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.repository.user_repository import UserRepository

create_user_dto = CreateUserDto(
    provider="kakao",
    provider_id=12345
)


def test_create_user_when_get_provider_id(session):
    UserRepository().create_user(dto=create_user_dto)
    user = session.query(UserModel).first()

    assert user.provider == create_user_dto.provider
    assert user.provider_id == create_user_dto.provider_id


# def test_get_user(session, create_users):
#     user_entity = UserRepository().get_user(user_id=)
#
#     assert user_entity == user.to_entity()


def test_create_user_when_use_create_users_fixture_then_make_two_users(
        session, create_users):
    """
    todo : Factory_boy를 활용한 테스트 케이스 추가
    """
    users = session.query(UserModel).all()

    assert len(users) == 2
    for i in range(2):
        assert users[i].provider in ("kakao", "naver")


def test_compare_create_user_when_use_build_batch_and_create_users_fixture(
        session, create_users, user_factory):
    fixture_users = session.query(UserModel).all()
    build_batch_users = user_factory.build_batch(size=3, provider="kakao")

    assert len(fixture_users) == 2
    assert len(build_batch_users) == 3
    assert fixture_users[0].id != build_batch_users[0].id
