from app.persistence.model.user_model import UserModel
from core.domains.user.repository.user_repository import UserRepository


def test_create_user_when_not_use_factory_boy(session):
    user = UserModel(nickname="Noah")
    session.add(user)
    session.commit()

    result = session.query(UserModel).first()

    assert result.nickname == user.nickname


def test_get_user(session):
    user = UserModel(nickname="Tester")
    session.add(user)
    session.commit()

    user_entity = UserRepository().get_user(user_id=user.id)

    assert user_entity == user.to_entity()


def test_create_user_when_use_create_users_fixture_then_make_two_users(session, create_users):
    users = session.query(UserModel).all()

    assert len(users) == 2
    assert users[0].nickname == "test_user_0"


def test_compare_create_user_when_use_build_batch_and_create_users_fixture(session, create_users, normal_user_factory):
    fixture_users = session.query(UserModel).all()
    build_batch_users = normal_user_factory.build_batch(size=3, nickname="Noah", sex="F")

    assert len(fixture_users) == 2
    assert len(build_batch_users) == 3
    assert fixture_users[0].sex != build_batch_users[0].sex == 'F'