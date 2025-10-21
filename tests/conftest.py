import sys
import types
from pathlib import Path


def _ensure_repo_root() -> None:
    root_path = Path(__file__).resolve().parents[1]
    root_str = str(root_path)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def _ensure_engine_path() -> None:
    src_path = Path(__file__).resolve().parents[1] / "infra" / "sam-app" / "src"
    src_str = str(src_path)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)


def _ensure_botocore_stub() -> None:
    if "botocore.exceptions" in sys.modules:
        return

    botocore_mod = types.ModuleType("botocore")
    exceptions_mod = types.ModuleType("botocore.exceptions")

    class ClientError(Exception):
        """Lightweight stand-in for botocore.exceptions.ClientError."""

        def __init__(self, error_response=None, operation_name=None):
            super().__init__(error_response, operation_name)
            self.response = error_response or {}
            self.operation_name = operation_name

    exceptions_mod.ClientError = ClientError
    botocore_mod.exceptions = exceptions_mod

    sys.modules["botocore"] = botocore_mod
    sys.modules["botocore.exceptions"] = exceptions_mod


def _ensure_boto3_stub() -> None:
    if "boto3" in sys.modules:
        return

    boto3_mod = types.ModuleType("boto3")

    class _FakeTable:
        def put_item(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def query(self, **kwargs):
            return {"Items": []}

        def update_item(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    class _FakeDynamoResource:
        def Table(self, name):
            return _FakeTable()

    class _GenericClient:
        def __getattr__(self, name):
            def _missing(*args, **kwargs):
                raise NotImplementedError(f"{name} not implemented in boto3 stub client")

            return _missing

    class _FakeS3Client(_GenericClient):
        def put_object(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def generate_presigned_url(self, **kwargs):
            key = kwargs.get("Params", {}).get("Key", "object")
            return f"https://example.com/{key}"

    def resource(service_name, *args, **kwargs):
        if service_name == "dynamodb":
            return _FakeDynamoResource()
        return _GenericClient()

    def client(service_name, *args, **kwargs):
        if service_name == "s3":
            return _FakeS3Client()
        return _GenericClient()

    boto3_mod.resource = resource
    boto3_mod.client = client

    sys.modules["boto3"] = boto3_mod
    dynamodb_mod = types.ModuleType("boto3.dynamodb")
    conditions_mod = types.ModuleType("boto3.dynamodb.conditions")

    class Key:
        def __init__(self, name):
            self.name = name

        def eq(self, value):
            return ("eq", self.name, value)

    conditions_mod.Key = Key
    dynamodb_mod.conditions = conditions_mod

    sys.modules["boto3.dynamodb"] = dynamodb_mod
    sys.modules["boto3.dynamodb.conditions"] = conditions_mod


_ensure_repo_root()
_ensure_engine_path()
_ensure_botocore_stub()
_ensure_boto3_stub()
