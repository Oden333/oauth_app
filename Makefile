.PHONY: vendor
vendor: 
	go mod tidy && go mod vendor

.PHONY: server/start
server/start:
	cd cmd && go run main.go

.PHONY: infra/start
infra/start:
	docker-compose -f docker-compose.yml up -d  --remove-orphans

.PHONY: infra/stop
infra/stop:
	docker-compose -f docker-compose.yml down

GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0

.PHONY: build/app
build/app:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o build/app cmd/main.go