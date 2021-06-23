# `python-base` sets up all shared environment variables
FROM python:3.8-slim-buster as python-base
MAINTAINER Noah

    # python
ENV PYTHONUNBUFFERED=1 \
    # prevents python creating .pyc files
    PYTHONDONTWRITEBYTECODE=1 \
    \
    # pip
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    \
    # poetry
    # https://python-poetry.org/docs/configuration/#using-environment-variables
    POETRY_VERSION=1.1.4 \
    # make poetry install to this location
    POETRY_HOME="/opt/poetry" \
    # make poetry create the virtual environment in the project's root
    # it gets named `.venv`
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    # do not ask any interactive question
    POETRY_NO_INTERACTION=1 \
    \
    # paths
    # this is where our requirements + virtual environment will live
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"


# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

FROM python-base as builder-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils \
        gcc \
        curl

# install poetry - respects $POETRY_VERSION & $POETRY_HOME
RUN curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python

# cleanup
 RUN rm -rf /var/lib/apt/lists/*

WORKDIR $PYSETUP_PATH
COPY poetry.lock pyproject.toml ./

# install runtime - uses $POETRY_VIRTUALENVS_IN_PROJECT internally
# but not install all dev pacakges
RUN poetry install --no-dev

# image used for runtime
FROM python-base as runtime-image
COPY --from=builder-base $PYSETUP_PATH $PYSETUP_PATH

# application root
ENV APP_DIR /server
COPY app ${APP_DIR}/app
COPY core ${APP_DIR}/core
COPY application.py VERSION newrelic.ini ${APP_DIR}/

EXPOSE 5000
WORKDIR ${APP_DIR}/
