NAME=mihomo
BINDIR=bin
BRANCH=$(shell git branch --show-current)
ifeq ($(BRANCH),feat/5gpn-monolith)
VERSION=monolith-$(shell git rev-parse --short HEAD)
else ifeq ($(BRANCH),)
VERSION=$(shell git describe --tags)
else
VERSION=$(shell git rev-parse --short HEAD)
endif

BUILDTIME=$(shell date -u)
GOBUILD=CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags '-X "github.com/metacubex/mihomo/constant.Version=$(VERSION)" \
		-X "github.com/metacubex/mihomo/constant.BuildTime=$(BUILDTIME)" \
		-w -s -buildid='

SUPPORTED_LINUX_TARGETS = \
	linux-386 \
	linux-386-softfloat \
	linux-amd64-compatible \
	linux-amd64 \
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-armv5 \
	linux-armv6 \
	linux-armv7 \
	linux-arm64 \
	linux-mips64 \
	linux-mips64le \
	linux-mips-softfloat \
	linux-mips-hardfloat \
	linux-mipsle-softfloat \
	linux-mipsle-hardfloat \
	linux-riscv64 \
	linux-loong64-abi2 \
	linux-s390x \
	linux-ppc64le

SUPPORTED_WINDOWS_TARGETS = \
	windows-386 \
	windows-amd64-compatible \
	windows-amd64 \
	windows-amd64-v1 \
	windows-amd64-v2 \
	windows-amd64-v3 \
	windows-arm64

all: linux-amd64-compatible linux-arm64 windows-amd64-compatible windows-arm64

linux-386:
	GOARCH=386 GOOS=linux GO386=sse2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-386-softfloat:
	GOARCH=386 GOOS=linux GO386=softfloat $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-compatible:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v1:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v2:
	GOARCH=amd64 GOOS=linux GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v3:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv5:
	GOARCH=arm GOOS=linux GOARM=5 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv7:
	GOARCH=arm GOOS=linux GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64:
	GOARCH=mips64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-riscv64:
	GOARCH=riscv64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-loong64-abi2:
	GOARCH=loong64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-s390x:
	GOARCH=s390x GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-ppc64le:
	GOARCH=ppc64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

windows-386:
	GOARCH=386 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-compatible:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v1:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v2:
	GOARCH=amd64 GOOS=windows GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v3:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm64:
	GOARCH=arm64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

gz_releases=$(addsuffix .gz, $(SUPPORTED_LINUX_TARGETS))
zip_releases=$(addsuffix .zip, $(SUPPORTED_WINDOWS_TARGETS))

$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe

all-arch: $(SUPPORTED_LINUX_TARGETS) $(SUPPORTED_WINDOWS_TARGETS)

releases: $(gz_releases) $(zip_releases)

vet:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINDIR)/*

CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
