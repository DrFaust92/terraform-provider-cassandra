TEST?=./...
CASSANDRA_VERSION?=5.0
COMPOSE_BIN?=$(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo docker-compose)
COMPOSE=$(COMPOSE_BIN) -f tests/docker-compose.yaml

export CASSANDRA_HOST?=127.0.0.1
export CASSANDRA_USERNAME?=cassandra
export CASSANDRA_PASSWORD?=cassandra

default: build

build: fmtcheck
	go install

test: fmtcheck
	go test $(TEST) $(TESTARGS) -timeout=30s -parallel=4

# Run acceptance tests against an already running Cassandra (see testacc_setup).
testacc: fmtcheck
	TF_ACC=1 go test ./cassandra -v $(TESTARGS) -timeout 120m

testacc_setup:
	CASSANDRA_VERSION=$(CASSANDRA_VERSION) $(COMPOSE) up -d --wait

testacc_cleanup:
	$(COMPOSE) down -v

vet:
	go vet ./...

fmt:
	gofmt -s -w .

docs:
	go generate ./...

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

lint:
	golangci-lint run ./...

.PHONY: docs build test testacc testacc_setup testacc_cleanup vet fmt fmtcheck lint
