GOPKG = github.com/yahoo/k8s-athenz-identity

REPO               ?= local
TAG                 = $(shell date -u +%Y%m%d-%H%M%S)
INIT_IMAGE          = k8s-athenz-initializer
AGENT_IMAGE         = k8s-athenz-identity-agent
CALLBACK_IMAGE      = k8s-athenz-callback
JWT_SERVICE_IMAGE   = k8s-athenz-jwt-service
SIA_IMAGE           = k8s-athenz-sia
SIA_CONTROL_IMAGE   = k8s-athenz-control-sia
MOCK_ATHENZ_IMAGE   = k8s-mock-athenz
TEST_APP_IMAGE      = k8s-athenz-test-app

images: build
	mkdir -p _build/bin
	cp $(GOPATH)/bin/athenz* _build/bin/
	docker build -f Dockerfile.initializer -t $(REPO)/$(INIT_IMAGE) .
	docker build -f Dockerfile.identity-agent -t $(REPO)/$(AGENT_IMAGE) .
	docker build -f Dockerfile.jwt-service -t $(REPO)/$(JWT_SERVICE_IMAGE) .
	docker build -f Dockerfile.callback -t $(REPO)/$(CALLBACK_IMAGE) .
	docker build -f Dockerfile.sia -t $(REPO)/$(SIA_IMAGE) .
	docker build -f Dockerfile.control-sia -t $(REPO)/$(SIA_CONTROL_IMAGE) .
	docker build -f Dockerfile.mock-athenz -t $(REPO)/$(MOCK_ATHENZ_IMAGE) .
	docker build -f Dockerfile.test-app -t $(REPO)/$(TEST_APP_IMAGE) .

build:
	dep ensure
	go install $(GOPKG)/...
	go test -v $(GOPKG)/...

