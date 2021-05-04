from app.persistence.model.user_model import UserModel
from core.domains.user.repository.user_repository import UserRepository


def test_create_user_when_not_use_factory_boy(session):
    user = UserModel(provider="kakao")
    session.add(user)
    session.commit()

    result = session.query(UserModel).first()

    assert result.provider == user.provider


def test_get_user(session):
    user = UserModel(provider="kakao")
    session.add(user)
    session.commit()

    user_entity = UserRepository().get_user(user_id=user.id)

    assert user_entity == user.to_entity()


def test_create_user_when_use_create_users_fixture_then_make_two_users(session, create_users):
    """
    todo : Factory_boy를 활용한 테스트 케이스 추가
    """
    users = session.query(UserModel).all()

    assert len(users) == 2
    for i in range(2):
        assert users[i].provider in ("kakao", "naver")


def test_compare_create_user_when_use_build_batch_and_create_users_fixture(session, create_users, normal_user_factory):
    fixture_users = session.query(UserModel).all()
    build_batch_users = normal_user_factory.build_batch(size=3, provider="kakao")

    assert len(fixture_users) == 2
    assert len(build_batch_users) == 3
    assert fixture_users[0].id != build_batch_users[0].id
