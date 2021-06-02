from __future__ import annotations

import argparse
import base64
import logging
import os
import sys
from pathlib import Path, PosixPath
from typing import Optional

import boto3
import docker
from botocore.exceptions import ClientError
from docker import DockerClient
from docker.models.images import Image

# constants
REPO_URL = "https://ap-northeast-2.console.aws.amazon.com/ecr/repositories/"

# argparser
parser = argparse.ArgumentParser(description="Build image.")
parser.add_argument("-e", "--environment", type=str, help="Specify environment")
parser.add_argument("-v", "--v", type=int, help="Specify a version.")
parser.add_argument("-d", "--debug", action="store_true", help="DEBUG")

# logger
logging.basicConfig(format="[%(levelname)s]\t%(message)s", level=logging.INFO)


# utils
def intify(l: list):
    for i in l:
        try:
            yield int(i)
        except ValueError:
            pass


# constants
IMAGE_NAME = "apartalk-api-dev"
BASE_DIR = Path(__file__).absolute().parent.parent
AVAILABLE_ENVIRONMENT = ["dev", "prod"]


class ECRPush:
    def __init__(self) -> None:
        self.docker_client = None

    def get_client(self):
        try:
            return boto3.client("ecr", region_name="ap-northeast-2")
        except ClientError as e:
            self.fail("Failed to create boto3 client.\n" + str(e))

    def get_docker_client(self) -> DockerClient:
        if self.docker_client:
            return self.docker_client

        self.docker_client = docker.from_env()
        return self.docker_client

    def get_version(self) -> int:
        args = parser.parse_args()
        return args.v or (self.get_latest_tag() + 1)

    @property
    def image_name(self) -> str:
        env = self.environment
        if env == "dev":
            return "apartalk/captain-api-dev"

        if env == "prod":
            return "apartalk/captain-api-prod"

    @property
    def dockerfile(self) -> PosixPath:
        return BASE_DIR / "Dockerfile"

    @property
    def environment(self) -> str:
        args = parser.parse_args()
        env = args.environment or os.getenv("BUILD_ENVIRONMENT", "dev")
        if env.lower() not in AVAILABLE_ENVIRONMENT:
            self.fail(f'"{env}" IS NOT AN AVAILABLE ENVIRONMENT')

        return env.lower()

    def get_latest_tag(
        self, previous_result: Optional[list] = None, next_token: Optional[str] = None
    ) -> str:
        client = self.get_client()
        if next_token:
            response = client.describe_images(
                repositoryName=self.image_name,
                nextToken=next_token,
                filter=dict(tagStatus="TAGGED"),
            )
        else:
            response = client.describe_images(
                repositoryName=self.image_name, filter=dict(tagStatus="TAGGED")
            )
        details = response.get("imageDetails", []) + (previous_result or [])
        response_next_token = response.get("nextToken")

        if not response_next_token and not details:
            return 1

        if not response_next_token and details:
            images = sorted(details, key=lambda i: i.get("imagePushedAt"), reverse=True)
            image_tags = images[0].get("imageTags", [])
            intified_tags = sorted(intify(image_tags), reverse=True)
            return 1 if not intified_tags else intified_tags[0]

        return self.get_latest_tag(details, response_next_token)

    def docker_login(self, docker_client: DockerClient) -> dict:
        client = self.get_client()
        response = client.get_authorization_token()
        b64token = response["authorizationData"][0]["authorizationToken"]
        username, password = base64.b64decode(b64token).decode("utf-8").split(":")

        registry = response["authorizationData"][0]["proxyEndpoint"]

        try:
            docker_client.login(username=username, password=password, registry=registry)
        except docker.errors.APIError as error:
            self.fail(f"Docker login error: {error}")

        logging.info(f"Successfully logged in to {registry}")

        return {"username": username, "password": password, "registry": registry}

    def push(
        self, docker_client: DockerClient, image: Image, tag: int, credentials: dict
    ) -> None:
        server_address = credentials.get("registry", "").split("//")[1]
        self.tag_image(image, tag, server_address)
        self.push_image(tag, server_address, credentials)

    def tag_image(self, image: Image, tag: str, server_address: str) -> None:
        logging.info(f"Tagging {self.image_name} with {tag}")
        try:
            result = image.tag(f"{server_address}/{self.image_name}", tag=tag)
        except docker.errors.APIError as error:
            self.fail(f"Docker tag error: {error}")
        if not result:
            self.fail(f"Failed to apply tag: {tag}")
        logging.info(f"{self.image_name} tagged with {tag} successfully")

    def push_image(self, tag: int, server_address: str, credentials: dict) -> None:
        docker_client = self.get_docker_client()
        for line in docker_client.images.push(
            f"{server_address}/{self.image_name}",
            tag,
            stream=True,
            decode=True,
            auth_config=credentials,
        ):
            self.debug_log(line)
            if line.get("error") is not None:
                self.fail(f"Docker push error: {line['errorDetail']['message']}")

    def build_image(self, docker_client):
        logging.info(f"Building {self.image_name}")
        image, _ = docker_client.images.build(
            path=str(BASE_DIR), dockerfile=str(self.dockerfile), tag=self.image_name
        )
        logging.info(f"{self.image_name} image built successfully")
        return image

    def run(self):
        tag = self.get_version()
        docker_client = self.get_docker_client()
        image = self.build_image(docker_client)
        credentials = self.docker_login(docker_client)
        server_address = credentials.get("registry", "").split("//")[1]
        self.push(docker_client, image, tag, credentials)
        self.success()

    def success(self) -> None:
        logging.info(
            f"https://ap-northeast-2.console.aws.amazon.com/ecr/repositories/{self.image_name}"
        )
        sys.exit(0)

    def fail(self, message: str = "") -> None:
        logging.error(f"💥  {message}")
        sys.exit(1)

    def debug_log(self, msg, *args, **kwargs):
        debug = parser.parse_args().debug
        if debug:
            logging.info(f"🌴  {msg}", *args, **kwargs)


if __name__ == "__main__":
    pipe = ECRPush()
    pipe.run()
