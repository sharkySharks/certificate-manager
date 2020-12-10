include .env
SHELL := /bin/bash

.PHONY: gofmt run_app test_postgres delete_app
gofmt:
	@echo "Formatting files..."
	gofmt -s -l -w .

run_app:
	docker-compose -f certificate-manager/docker-compose.yml down
	docker-compose -f certificate-manager/docker-compose.yml up --build --abort-on-container-exit
	docker-compose -f certificate-manager/docker-compose.yml down

delete_app:
	docker-compose -f certificate-manager/docker-compose.yml down --volumes

test_postgres:
	docker-compose -f postgres/docker-compose.yml down --volumes
	docker-compose -f postgres/docker-compose.yml up --build --abort-on-container-exit
	docker-compose -f postgres/docker-compose.yml down --volumes
