.PHONY: test build verify-local e2e e2e-stack protected-up protected-down native release-check

TEST_ROOTS := detection-engine host-agent

test:
	cd detection-engine && go test ./... && go vet ./...
	cd host-agent && go test ./... && go vet ./...
	cd llm-orchestration && PYTHONPATH=. python3 -m unittest -v test_safety.py && python3 -m py_compile app.py orchestrator.py ollama_client.py agents/*.py

build:
	cd detection-engine && go build ./...
	cd host-agent && go build ./...

verify-local: test build
	python3 scripts/validate-config.py

native:
	./scripts/build-native.sh

e2e:
	./scripts/e2e-local.sh

e2e-stack:
	./scripts/e2e-stack.sh

release-check:
	./scripts/release-check.sh

protected-up:
	./deploy/bootstrap.sh
	docker compose --env-file deploy/.env -f deploy/docker-compose.protected-host.yml up -d --build

protected-down:
	docker compose --env-file deploy/.env -f deploy/docker-compose.protected-host.yml down --remove-orphans
