# What is [captain](https://bitbucket.org/apartalk/captain/src)?
* starting point of toadhome
* schema project
* domain driven design
* version 
    * python : 3.8
    * flask : 1.1.2
# Usage
## [poetry](https://python-poetry.org/)
* install poetry : `curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python`
* set env
```
$ vi ~/.zshrc
  export PATH="$HOME/.poetry/bin:$PATH"
```
* install packages in poetry.lock : `poetry install`
* install package : `poetry add {package name}`
* uninstall package : `pipenv remove {package name}`
* dependencies update - newest version : `poetry update`
* show pakage : `poery show`
* env info : `poery env info`
## [flask-migrate](https://flask-migrate.readthedocs.io/en/latest/)
* create empty migration file : `flask db revision -m "create {name} table"`
* create auto-generate migrate file : `flask db migrate -m "create {name} table"`
    * `model에 설정된대로 revision 파일을 만들어주기 때문에 편리하다.`
    * `migrations/env.py의 target_metadata에 db.Model.metadata를 넣어줘야 한다.`
* db upgrade : `flask db upgrade`
* db downgrade : `flask db downgrade`
* target current db : `flask db stamp {revision}`
    * 사용해야할 상황
        1. `진행된 마이그레이션과 현재 alembic이 가리키고 있는 마이그레이션이 다른 경우 동기화`
        2. `아직 진행되지 않은, 혹은 downgrade로 db 롤백 후 마이그레이션 파일 삭제하기 전에 가리키려는 revision을 지정하고 파일 삭제`
    * `revision에는 head나 revision이 들어가면 된다.`
## [pydantic](https://pydantic-docs.helpmanual.io/)
* python schema validator
* validate request parameter, dto, response schema
## [pypubsub](https://pypubsub.readthedocs.io/en/latest/)
* python event pubsub for observer pattern

```python
# initialize event listener in app/__init__.py
# event listener initialization
from core.domains.board import event
```
A 도메인이 B 도메인의 리스너를 필요로 할 때 topic enum과 리스너는 B 도메인에 존재해야 한다.
```python
from flask import g
from pubsub import pub

# 구독 중인 topic에 이벤트가 발생하도록 한다.
def send_message(topic_name: str = None, **kwargs):
    pub.sendMessage(topicName=topic_name, **kwargs)

# g 변수에 저장된 값을 topic_name key로 가져온다.
def get_event_object(topic_name: str = None):
    return getattr(g, topic_name, None)

# 리스너가 바라보는 topic 지정 후 리스너에서 사용할 매개변수를 kwargs 형식으로 넘긴다.
send_message(topic_name="topic_name", user_id=1)

# 리스너로부터 생성된 값을 topic key로 가져온다.
get_event_object(topic_name="topic_name")
```
## [swagger](https://swagger.io/docs/specification/basic-structure/)
* api docs
* 실행 환경의 DB 데이터에 따라 결과 값을 직접 호출해볼 수 있다.
* 로컬에서 `http://127.0.0.1:5000/{domain}/apidocs` 접속 후 `authorize`에 적절한 토큰과 `request parameter`를 넣고 `try it out`, `execute` 클릭한다.
* api doc 추가 시 view 파일 위에 `swag_from` 데코레이터 사용해서 yml 파일 명시한다.
* 프로젝트 변경 등으로 인한 api prefix 수정 시 `swagger/__init__.py` 에서 `static_url_path`, `specs_route` 등 수정해야 한다. 
