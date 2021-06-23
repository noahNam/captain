from __future__ import annotations

import hashlib
import json
import sys

import boto3


class BlueGreenDeploy:
    """
    Currently this class only works for prod-captain-api.
    It does not work for captain-cron-prod or captain-consumer-prod
    """

    @property
    def ecs_client(self):
        return boto3.client("ecs", region_name="ap-northeast-2")

    @property
    def code_deploy_client(self):
        return boto3.client("codedeploy", region_name="ap-northeast-2")

    @property
    def base_appspec(self) -> dict:
        return {
            "version": 1,
            "Resources": [
                {
                    "TargetService": {
                        "Type": "AWS::ECS::Service",
                        "Properties": {
                            "TaskDefinition": "__TASK_DEFINITION__",
                            "LoadBalancerInfo": {
                                "ContainerName": "prod-captain-api",
                                "ContainerPort": 5000,
                            },
                        },
                    }
                }
            ],
        }

    def get_latest_task(self) -> str:
        response = self.ecs_client.list_task_definitions(
            familyPrefix="prod-captain-api", status="ACTIVE", sort="DESC"
        )
        arns = response.get("taskDefinitionArns", [])
        return arns[0]

    def create_appspec_content(self, task_definition: str) -> str:
        app_spec_str = json.dumps(self.base_appspec)
        final_app_spec = app_spec_str.replace("__TASK_DEFINITION__", task_definition)
        encoded_app_spec = final_app_spec.encode()
        return {
            "content": final_app_spec,
            "sha256": hashlib.sha256(encoded_app_spec).hexdigest(),
        }

    def create_deployment(self, app_spec_content: str) -> None:
        deploy_result = self.code_deploy_client.create_deployment(
            applicationName="AppECS-prod-captain-api-cluster-prod-captain-api",
            deploymentGroupName="DgpECS-prod-captain-api-cluster-prod-captain-api",
            deploymentConfigName="CodeDeployDefault.ECSAllAtOnce",
            revision={
                "revisionType": "AppSpecContent",
                "appSpecContent": app_spec_content,
            },
        )
        return deploy_result.get("deploymentId")

    def run(self) -> None:
        latest_task = self.get_latest_task()
        app_spec = self.create_appspec_content(latest_task)
        deploy_id = self.create_deployment(app_spec)
        self.success(deploy_id)
        return

    def success(self, deploy_id: str) -> None:
        print(
            f"https://ap-northeast-2.console.aws.amazon.com/codesuite/codedeploy/deployments/{deploy_id}?region=ap-northeast-2"
        )
        print("🚀🚀🚀 SUCCESSFULLY DEPLOYED 🚀🚀🚀")
        sys.exit(0)


if __name__ == "__main__":
    pipe = BlueGreenDeploy()
    pipe.run()
