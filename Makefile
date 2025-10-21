.PHONY: init scan deploy destroy

init:
	python3.11 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

scan:
	@. .venv/bin/activate && python -m minicspm.cli scan --format csv --out "out/minicspm-$$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo local)-$$(date -u +%Y%m%dT%H%M%SZ).csv" || exit 2

deploy:
	sam build --use-container
	sam deploy --stack-name mini-cspm --guided

destroy:
	sam delete --stack-name mini-cspm --no-prompts
