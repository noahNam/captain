from flask import Blueprint, Flask, jsonify

from app.__meta__ import __api_name__, __version__

main = Blueprint("main", __name__)


def init_main_blueprint(app: Flask):
    app.register_blueprint(main)


@main.route("/")
def index():
    return jsonify({"name": __api_name__, "version": __version__})
