import pytest
from datetime import date, timedelta, datetime
from faker import Faker
from tests.seeder.factory.data_service_factory import (
    NormalUserFactory,
)

MODEL_FACTORIES = [
    NormalUserFactory,
]


faker = Faker()


@pytest.fixture
def create_users(session, normal_user_factory):
    users = normal_user_factory.build_batch(2)

    session.add_all(users)
    session.commit()


def make_random_today_date(between_days: int = 1, year_ago: int = 2):
    """
        주어진 날의 00:00:00 ~ 23:59:59 사이의 랜덤 시간을 만든다.
        기본적으로 조회시간 기준 2년전으로 만듬
    """
    return faker.date_time_between_dates(
        datetime_start=date.today() - timedelta(days=365 * year_ago + between_days),
        datetime_end=datetime.now() - timedelta(days=365 * year_ago + between_days),
    )


def make_random_between_date(start_date, end_date):
    """주어진 날짜 사이의 랜덤 date 만든다 """
    return faker.date_time_between_dates(
        datetime_start=start_date, datetime_end=end_date
    )