#!/bin/bash
RELEASE_BIN_DIR='./bin/'
BINARY_NAME='gofly-server'
function create_dir() {
    if [ ! -d $1 ];then
        mkdir $1
    fi
}

function go_build() {
    suffix=''
    if [[ "$1" == "windows" ]]; then
        suffix='.exe'
    fi
    CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -o "${RELEASE_BIN_DIR}${BINARY_NAME}-$1_$2${suffix}" -ldflags "-w -s -X 'main._version=1.0.$(date +%Y%m%d)' -X 'main._goVersion=$(go version)' -X 'main._gitHash=$(git show -s --format=%H)' -X 'main._buildTime=$(git show -s --format=%cd)'" ./cmd
}

arch="unknown"
function get_arch() {
    res=$(uname -m)
    if [[ $res =~ "x86_64" ]]; then
        arch="amd64"
    elif [[ $res =~ "aarch64" ]]; then
        arch="arm64"
    fi
}

function main() {
    rm -rf $RELEASE_BIN_DIR
    go clean
    go mod tidy
    create_dir $RELEASE_BIN_DIR
    go_build linux amd64
    go_build linux arm64
    go_build darwin arm64
    go_build darwin amd64
    go_build windows amd64
    go_build windows arm64
    get_arch
    ${RELEASE_BIN_DIR}${BINARY_NAME}-linux_${arch} -v
}

main
