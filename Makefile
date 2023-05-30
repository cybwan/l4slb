#!make

TARGETS      := linux/amd64 linux/arm64
DIST_DIRS    := find * -type d -exec

GOPATH = $(shell go env GOPATH)
GOBIN  = $(GOPATH)/bin
GOX    = go run github.com/mitchellh/gox
SHA256 = sha256sum
ifeq ($(shell uname),Darwin)
	SHA256 = shasum -a 256
endif

VERSION ?= dev
BUILD_DATE ?=
GIT_SHA=$$(git rev-parse HEAD)
BUILD_DATE_VAR := github.com/cybwan/l4slb/pkg/version.BuildDate
BUILD_VERSION_VAR := github.com/cybwan/l4slb/pkg/version.Version
BUILD_GITCOMMIT_VAR := github.com/cybwan/l4slb/pkg/version.GitCommit

LDFLAGS ?= "-X $(BUILD_DATE_VAR)=$(BUILD_DATE) -X $(BUILD_VERSION_VAR)=$(VERSION) -X $(BUILD_GITCOMMIT_VAR)=$(GIT_SHA) -s -w"

# Installed Go version
# This is the version of Go going to be used to compile this project.
# It will be compared with the minimum requirements for ECNET.
GO_VERSION_MAJOR = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_VERSION_MINOR = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
GO_VERSION_PATCH = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f3)
ifeq ($(GO_VERSION_PATCH),)
GO_VERSION_PATCH := 0
endif

.PHONY: protos
protos:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	go get -u google.golang.org/grpc
	protoc --go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		pkg/pb/l4slb.proto

.PHONY: build-cli
build-cli:
	CGO_ENABLED=0 go build -v -o ./bin/slbc -ldflags ${LDFLAGS} ./cmd/slbc
	CGO_ENABLED=0 go build -v -o ./bin/slbd -ldflags ${LDFLAGS} ./cmd/slbd

.PHONY: clean-cli
clean-cli:
	@rm -rf bin/l4slbc
	@rm -rf bin/l4slbd


.PHONY: go-checks
go-checks: go-lint go-fmt go-mod-tidy

.PHONY: go-vet
go-vet:
	go vet ./...

.PHONY: go-lint
go-lint: embed-files-test
	docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v1.50 golangci-lint run --config .golangci.yml

.PHONY: go-fmt
go-fmt:
	go fmt ./...

.PHONY: go-mod-tidy
go-mod-tidy:
	./scripts/go-mod-tidy.sh

lint-c:
	clang-format --Werror -n bpf/*.c bpf/headers/*.h

format-c:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: shellcheck
shellcheck:
	shellcheck -x $(shell find . -name '*.sh')

.PHONY: install-git-pre-push-hook
install-git-pre-push-hook:
	./scripts/install-git-pre-push-hook.sh

# -------------------------------------------
#  release targets below
# -------------------------------------------

.PHONY: build-cross
build-cross:
	GO111MODULE=on CGO_ENABLED=0 $(GOX) -ldflags $(LDFLAGS) -parallel=5 -output="_dist/{{.OS}}-{{.Arch}}/slbd" -osarch='$(TARGETS)' ./cmd/slbd
	GO111MODULE=on CGO_ENABLED=0 $(GOX) -ldflags $(LDFLAGS) -parallel=5 -output="_dist/{{.OS}}-{{.Arch}}/slbc" -osarch='$(TARGETS)' ./cmd/slbc

.PHONY: dist
dist:
	( \
		cd _dist && \
		$(DIST_DIRS) cp ../LICENSE {} \; && \
		$(DIST_DIRS) cp ../README.md {} \; && \
		$(DIST_DIRS) tar -zcf flomesh-l4slb-${VERSION}-{}.tar.gz {} \; && \
		$(DIST_DIRS) zip -r flomesh-l4slb-${VERSION}-{}.zip {} \; && \
		$(SHA256) flomesh-l4slb-* > sha256sums.txt \
	)

.PHONY: release-artifacts
release-artifacts: build-cross dist

CLANG ?= clang
#CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CFLAGS := -O2 -g -Wall $(CFLAGS)

# $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

logs-bpf:
	sudo cat /sys/kernel/debug/tracing/trace_pipe | grep bpf_trace_printk

test-d:
	sudo ./bin/slbd

tcpdump-ens33:
	tcpdump -ni ens33 -e -p -vvv

tcpdump-ipip4:
	tcpdump -ni ipip4 -e -p -vvv

get-default-mac:
	ip n show | grep `ip route  | grep default | awk '{print $3}'` | awk '{print $5}'

test-mac-change:
	sudo ./bin/slbc -change_mac 00:0c:29:b0:bf:e7

test-mac-list:
	sudo ./bin/slbc -list_mac

test-mac: test-mac-change test-mac-list

init-r:
	sudo ip a add 192.168.226.80/32 dev lo:1
	sudo ip link add name ipip4 type ipip external
	sudo ip link add name ipip6 type ip6tnl external
	sudo ip link set up dev ipip4
	sudo ip link set up dev ipip6
	sudo ip a add dev ipip4 172.16.0.1/24
	sudo ip -6 a add dev ipip6 0100::0/64
	echo "1" >/proc/sys/net/ipv4/conf/lo/arp_ignore
	echo "2" >/proc/sys/net/ipv4/conf/lo/arp_announce
	echo "1" >/proc/sys/net/ipv4/conf/all/arp_ignore
	echo "2" >/proc/sys/net/ipv4/conf/all/arp_announce

init-d:
	sudo sysctl net.core.bpf_jit_enable=1
	sudo ip a add 192.168.226.80/32 dev ens36:1

run-d:
	./bin/slbd -default_route_device=ens36

test-c:
	sudo ./bin/slbc -change_mac 00:50:56:27:dc:b2
	sudo ./bin/slbc -A -t 192.168.226.80:80
	sudo ./bin/slbc -a -t 192.168.226.80:80 -r 192.168.226.81

test-app:
	curl http://192.168.127.80:80