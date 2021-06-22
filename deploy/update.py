from __future__ import annotations

import argparse
import base64
import logging
import os
import subprocess
import sys
from pathlib import Path
from shutil import which
from typing import Optional

import boto3
from botocore.exceptions import ClientError

# argparser
parser = argparse.ArgumentParser(description="Compose image.")
parser.add_argument("-e", "--environment", type=str, help="Specify environment")
parser.add_argument("-d", "--debug", action="store_true", help="DEBUG")
parser.add_argument("-s", "--service", type=str, help="Specify service (api / worker)")

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
BASE_DIR = Path(__file__).absolute().parent.parent
AVAILABLE_ENVIRONMENT = ["dev", "prod"]
AVAILABLE_SERVICE = ["api", "worker"]
ECS_BASE_URL = "https://ap-northeast-2.console.aws.amazon.com/ecs/home?region=ap-northeast-2#/clusters/"


class ECSCompose:
    def __init__(self) -> None:
        pass

    def get_client(self):
        try:
            return boto3.client("ecr", region_name="ap-northeast-2")
        except ClientError:
            self.fail("Failed to create boto3 client.\n" + str(e))

    @property
    def image(self) -> str:
        env = self.environment
        return f"toadhome/captain-api-{env}"

    @property
    def cluster(self) -> str:
        env = self.environment
        return f"{env}-captain-api-cluster"

    @property
    def service_type(self) -> str:
        args = parser.parse_args()
        if not args.service:
            self.fail(f"Please supply service.")
            return

        if args.service not in AVAILABLE_SERVICE:
            self.fail(f"service expected to be one of {AVAILABLE_SERVICE}")
            return

        return args.service

    @property
    def service(self) -> str:
        return f"{self.environment}-captain-{self.service_type}"

    @property
    def template(self) -> str:
        env = self.environment
        file_dir = (
            BASE_DIR
            / "deploy"
            / f"{env}"
            / f"docker-compose-ecs-{self.service_type}-{env}.yml"
        )
        f = open(file_dir, "r")
        return f.read()

    @property
    def params(self) -> str:
        env = self.environment
        service = self.service_type
        return str(
            BASE_DIR / "deploy" / f"{env}" / f"docker-ecs-params-{service}-{env}.yml"
        )

    @property
    def environment(self) -> str:
        args = parser.parse_args()
        env = args.environment or os.getenv("BUILD_ENVIRONMENT", "dev")
        if env.lower() not in AVAILABLE_ENVIRONMENT:
            self.fail(f'"{env}" IS NOT AN AVAILABLE ENVIRONMENT')

        return env.lower()

    @property
    def call_command(self) -> list:
        env = self.environment
        service_type = self.service_type

        if env == "dev" or (env == "prod" and service_type == "worker"):
            return [
                "ecs-cli",
                "compose",
                "--cluster",
                self.cluster,
                "--project-name",
                self.service,
                "--file",
                self.compose_file_dir,
                "--ecs-params",
                self.params,
                "service",
                "up",
                "--force-deployment",
                "--timeout",
                "10",
            ]
        elif env == "prod" and service_type == "api":
            return [
                "ecs-cli",
                "compose",
                "--cluster",
                self.cluster,
                "--project-name",
                self.service,
                "--file",
                self.compose_file_dir,
                "--ecs-params",
                self.params,
                "create",
            ]

    @property
    def ssm_parameter_name(self) -> str:
        env = self.environment
        if env == "dev":
            return f"/toadhome/{self.service}"

        if env == "prod":
            return f"/toadhome/{self.service}"

    def get_ssm_parameters(self) -> str:
        client = boto3.client("ssm")
        resp = client.get_parameter(Name=self.ssm_parameter_name)
        parameter = resp.get("Parameter")
        if not parameter:
            return self.fail(f"Failed to get parameter")

        values = parameter.get("Value")
        if not values:
            return self.fail(f"Failed to get parameter")

        return values

    def map_ssm(self) -> None:
        env_vars = self.get_ssm_parameters()
        with open(self.compose_file_dir, mode="a") as f:
            f.write(f"\n{env_vars}")

        with open(self.compose_file_dir, "r") as f:
            self.debug_log(f"{f.read()}")

    def get_server_address(self) -> str:
        client = self.get_client()
        response = client.get_authorization_token()
        b64token = response["authorizationData"][0]["authorizationToken"]
        username, password = base64.b64decode(b64token).decode("utf-8").split(":")

        registry = response["authorizationData"][0]["proxyEndpoint"]

        return registry.split("//")[1]

    def get_latest_tag(
        self, previous_result: Optional[list] = None, next_token: Optional[str] = None
    ) -> int:
        client = self.get_client()
        if next_token:
            response = client.describe_images(
                repositoryName=self.image,
                nextToken=next_token,
                filter=dict(tagStatus="TAGGED"),
            )
        else:
            response = client.describe_images(
                repositoryName=self.image, filter=dict(tagStatus="TAGGED")
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

    @property
    def compose_file_dir(self) -> str:
        file_dir = str(BASE_DIR / "deploy" / f"{self.service}.yml")
        return file_dir

    def create_compose_file(self, server_address: str, version: int) -> str:
        template = self.template.replace(
            "__ECR_ADDRESS__", f"{server_address}/{self.image}:{version}"
        )
        f = open(self.compose_file_dir, "w")
        f.write(template)
        f.close()
        self.debug_log(template)

    def call(self) -> tuple:
        popen = subprocess.Popen(
            " ".join(self.call_command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )

        line = popen.stdout.readline().decode("utf8")
        while line:
            if (
                "has begun draining connections on 1 tasks" in line
                and self.environment == "dev"
            ):
                logging.info(
                    f"⚡ For faster deployment please shutdown old task manually\n"
                    f"📬 {ECS_BASE_URL}{self.cluster}/services/{self.service}/tasks"
                )

            if "level=error" in line or "level=fatal" in line:
                return self.fail(line)

            logging.info(f"💨 {line}")
            line = popen.stdout.readline().decode("utf8")

    def run(self) -> None:
        server_address = self.get_server_address()
        version = self.get_latest_tag()
        logging.info(f"🦄 Using version {version}")
        self.create_compose_file(server_address, version)
        self.map_ssm()
        self.call()
        self.success()

    def is_ecs_cli_available(self) -> None:
        if which("ecs-cli") is not None:
            return

        self.fail(f"ecs-cli must be installed")

    def success(self) -> None:
        self.remove()
        print("🚀🚀🚀 SUCCESSFULLY DEPLOYED 🚀🚀🚀")
        sys.exit(0)

    def remove(self) -> None:
        if os.path.isfile(self.compose_file_dir):
            self.debug_log(f"{self.compose_file_dir} exists. Removing it.")
            os.remove(self.compose_file_dir)

    def fail(self, message: str = "") -> None:
        logging.error(f"💥  {message}")
        sys.exit(1)

    def debug_log(self, msg, *args, **kwargs):
        debug = parser.parse_args().debug
        if debug:
            logging.info(f"🌴  {msg}", *args, **kwargs)


if __name__ == "__main__":
    pipe = ECSCompose()
    try:
        pipe.run()
    except BaseException as e:
        pipe.remove()
        raise e
