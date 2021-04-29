swagger_config = {
    "openapi": "3.0.2",
    "info": {
        "description": "powered by Flasgger",
        "termsOfService": "/captain",
        "title": "A swagger API",
        "version": "1.0.0",
    },
    "host": "localhost:5000",
    "basePath": "/captain/",
    "components": {
        "schemas": ["http", "https"],
        "securitySchemes": {
            "userAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "user jwt token 사용",
            }
        },
        "servers": [
            {"url": "http://localhost:5000/", "description": "local server"},
            {
                "url": "https://development-server.com",
                "description": "development server",
            },
            {
                "url": "https://production-server.com",
                "description": "production server",
            },
        ],
    },
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/captain/apidocs/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/captain/apidocs/",
}
