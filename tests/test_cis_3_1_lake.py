from datetime import datetime, timezone

from checks import cis_3_1_unauth_api_metric_filter as control
from models import Finding
from settings import Settings


class _CloudTrailLakeStub:
    def __init__(self, counts):
        self.counts = counts
        self.started = False

    def start_query(self, QueryStatement):
        self.started = True
        return {"QueryId": "abc"}

    def get_query_status(self, QueryId):
        return {"QueryStatus": {"State": "FINISHED"}}

    def get_query_results(self, QueryId):
        rows = []
        for source, total in self.counts.items():
            rows.append(
                {
                    "Data": [
                        {"FieldName": "eventSource", "FieldValue": source},
                        {"FieldName": "total", "FieldValue": str(total)},
                    ]
                }
            )
        return {"QueryResultRows": rows}


def _settings(**overrides):
    base = dict(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        unauth_mode="lake",
        unauth_window_days=7,
        unauth_result_threshold=3,
        account_id="123456789012",
        aws_region="us-east-1",
    )
    base.update(overrides)
    return Settings(**base)


def test_lake_mode_fail():
    settings = _settings()
    clients = {"cloudtrail_lake": _CloudTrailLakeStub({"iam.amazonaws.com": 5})}
    finding = control.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"
    assert finding["evidence"]["unauthorized_count"] == 5


def test_lake_mode_pass_with_exclusions():
    settings = _settings(unauth_exclude_services="iam",
                         unauth_result_threshold=1)
    clients = {"cloudtrail_lake": _CloudTrailLakeStub({"iam.amazonaws.com": 5, "ec2.amazonaws.com": 1})}
    finding = control.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"
    assert finding["evidence"]["unauthorized_count"] == 1
