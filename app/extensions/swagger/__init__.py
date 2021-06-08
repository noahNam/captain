import fnmatch
import os

import yaml
from flask import current_app

from app.__meta__ import __api_name__, __version__

_swagger_schema: dict = {}

DESC = "captain swagger"


def swagger_config():
    return {
        "config": {
            "openapi": "3.0.2",
            "info": {
                "description": "powered by Flasgger",
                "termsOfService": "/docs/captain",
                "title": "A swagger API",
                "version": "1.0.0",
            },
            "host": "localhost:5000",
            "basePath": "/docs/captain/",
            "components": {
                "schemas": _swagger_schema,
                "securitySchemes": {
                    "userAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                        "description": "user jwt token 사용",
                    }
                },
                "servers": [
                    {"url": "http://localhost:5000/docs/captain/apidocs/", "description": "local server"},
                    {
                        "url": "https://www.apartalk.com/docs/captain/apidocs/",
                        "description": "development server",
                    },
                    {
                        "url": "https://www.apartalk.com/docs/captain/apidocs/",
                        "description": "production server",
                    },
                ],
            },
            "headers": [],
            "specs": [
                {
                    "endpoint": "apispec",
                    "route": "/docs/captain/apispec.json",
                    "rule_filter": lambda rule: True,  # all in
                    "model_filter": lambda tag: True,  # all in
                }
            ],
            "static_url_path": "/docs/captain/apidocs/flasgger_static",
            "swagger_ui": True,
            "specs_route": "/docs/captain/apidocs/",
        },
        "template": {
            "info": {
                "title": __api_name__,
                "version": __version__,
                "description": DESC,
                "contact": {
                    "responsibleOrganization": "Apartalk",
                    "responsibleDeveloper": "Noah",
                    "email": "",
                    "url": "",
                },
                "termsOfService": "",
            },
            "host": current_app.config.get("HOST_URL"),
            "basePath": "",  # base bash for blueprint registration
            "schemes": current_app.config.get("HOST_PROTOCOL"),
            "operationId": "getmyData",
        },
    }


def import_components() -> None:
    working_folder_path = os.path.dirname(os.path.realpath(__file__))
    for path, sub_dir, files in os.walk(working_folder_path):
        for file_name in files:
            if fnmatch.fnmatch(file_name, "*.yml"):
                definition_doc = yaml.full_load(open(os.path.join(path, file_name)))
                _swagger_schema.update(definition_doc)


import_components()
