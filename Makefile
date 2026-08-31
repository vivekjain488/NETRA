# NETRA developer workflow.
#
# Every target here is used by CI and by the demo runbook, so a command that
# works locally works the same way in the pipeline.

COMPOSE  := docker compose --env-file .env -f deployment/compose/docker-compose.yml
IDENTITY := $(COMPOSE) -f deployment/compose/identity.yml

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: env
env: ## Create .env, generating a random value for every blank secret
	@./scripts/init-env.sh

.PHONY: up
up: env ## Start the local stack (postgres, backend, dashboard)
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop the stack, keeping data
	$(IDENTITY) down

.PHONY: clean
clean: ## Stop the stack and delete its data volume
	$(IDENTITY) down -v

.PHONY: identity-up
identity-up: env ## Start the stack including Keycloak
	$(IDENTITY) up -d --build

.PHONY: identity-passwords
identity-passwords: ## Apply demo user passwords from .env to Keycloak
	@set -a; . ./.env; set +a; ./deployment/keycloak/set-demo-passwords.sh

.PHONY: logs
logs: ## Follow backend logs
	$(COMPOSE) logs -f backend

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps

.PHONY: test
test: test-backend test-agent test-dashboard ## Run every test suite

.PHONY: test-backend
test-backend: ## Run Go tests
	cd backend && go vet ./... && go test ./...

.PHONY: test-agent
test-agent: ## Run Rust tests
	cd agent && cargo test

.PHONY: test-dashboard
test-dashboard: ## Run dashboard tests and typecheck
	cd dashboard && npm run lint && npm test

.PHONY: build
build: ## Build every component
	cd backend && go build ./...
	cd agent && cargo build
	cd dashboard && npm run build
	cd electron && npm run build

.PHONY: audit
audit: ## Check dependencies for known vulnerabilities
	cd dashboard && npm audit --audit-level=moderate
	cd electron && npm audit --audit-level=moderate

.PHONY: run-agent
run-agent: ## Run the endpoint agent in the foreground
	cd agent && cargo run --bin netra-agent

.PHONY: run-client
run-client: ## Build and launch the Electron client
	cd electron && npm run start
