#!/bin/sh
#
# Build binaries and checksums and place them in the `release/` directory

cd $( dirname $0 ) # use this directory for relative paths
set -e             # exit on non-zero responses
set -x             # print commands to the terminal

# disable CGO for cross-compiling
export CGO_ENABLED=0

# compile for all architectures
GOOS=linux   GOARCH=amd64 go build -mod=vendor -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/amd64/redactr       ./cmd/redactr
GOOS=linux   GOARCH=arm64 go build -mod=vendor -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/arm64/redactr       ./cmd/redactr
GOOS=linux   GOARCH=arm   go build -mod=vendor -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/arm/redactr         ./cmd/redactr
GOOS=windows GOARCH=amd64 go build -mod=vendor -ldflags "-X main.version=${DRONE_TAG##v}" -o release/windows/amd64/redactr.exe ./cmd/redactr
GOOS=darwin  GOARCH=amd64 go build -mod=vendor -ldflags "-X main.version=${DRONE_TAG##v}" -o release/darwin/amd64/redactr      ./cmd/redactr

# tar binary files prior to upload
tar -cvzf release/redactr_linux_amd64.tar.gz   -C release/linux/amd64   redactr
tar -cvzf release/redactr_linux_arm64.tar.gz   -C release/linux/arm64   redactr
tar -cvzf release/redactr_linux_arm.tar.gz     -C release/linux/arm     redactr
tar -cvzf release/redactr_windows_amd64.tar.gz -C release/windows/amd64 redactr.exe
tar -cvzf release/redactr_darwin_amd64.tar.gz  -C release/darwin/amd64  redactr

# generate shas for tar files
sha256sum release/*.tar.gz > release/redactr_checksums.txt