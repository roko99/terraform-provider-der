TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=local
NAMESPACE=roko99
NAME=der
BINARY=terraform-provider-${NAME}
VERSION=0.1.0
OS_ARCH=darwin_arm64

default: install

build:
	GO111MODULE=on go build -o ${BINARY}

release:
	GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	GO111MODULE=on GOOS=darwin GOARCH=arm64 go build -o ./bin/${BINARY}_${VERSION}_darwin_arm64
	GO111MODULE=on GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386
	GO111MODULE=on GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64
	GO111MODULE=on GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm
	GO111MODULE=on GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386
	GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64
	GO111MODULE=on GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm
	GO111MODULE=on GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386
	GO111MODULE=on GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64
	GO111MODULE=on GOOS=solaris GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_solaris_amd64
	GO111MODULE=on GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386
	GO111MODULE=on GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

example_clean:
	@cd examples && rm -f .terraform.lock.hcl terraform.tfstate .terraform.lock.hcl *.backup crash.log

example_run:
	@cd examples && terraform init && terraform apply --auto-approve

example_all: install example_clean example_run

fmt:
	gofmt -s -w .
	go mod tidy

lint:
	golangci-lint run

vet:
	go vet ./...

ci-test: vet test lint
	@echo "All CI checks passed!"

.PHONY: default build release install test testacc example_clean example_run example_all fmt lint vet ci-test
