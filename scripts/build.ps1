$RELEASE_BIN_DIR='.\bin\'
$BINARY_NAME='gofly-server'
function removeDir() {
    Remove-Item -Path $RELEASE_BIN_DIR -Recurse
}

function createDir() {
    if (Test-Path -Path $RELEASE_BIN_DIR) {
        echo "path exists"
    } else {
        echo "path not exists"
        New-Item -Path $RELEASE_BIN_DIR -ItemType Directory
    }
}

function goBuild() {
    param(
        [string]$os,
        [string]$arch
    )
    $suffix=''
    if ($os -like "windows") {
        $suffix='.exe'
    }
    $versionCode=Get-Date -format "yyyyMMdd"
    $goVersion=go version
    $gitHash=git log --pretty=format:'%h' -n 1
    $buildTime=git log --pretty=format:'%cd' -n 1
    set CGO_ENABLED=0
    set GOOS=$os
    go env -w GOOS=$os
    set GOARCH=$arch
    go env -w GOARCH=$arch
    go build -o $RELEASE_BIN_DIR$BINARY_NAME-${os}_$arch$suffix -ldflags "-w -s -X 'main._version=1.0.$versionCode' -X 'main._goVersion=$goVersion' -X 'main._gitHash=$gitHash' -X 'main._buildTime=$buildTime'" ./cmd
}

function main() {
    removeDir
    go clean
    go mod tidy
    createDir
    goBuild linux amd64
    goBuild linux arm64
    goBuild darwin arm64
    goBuild darwin amd64
    goBuild windows amd64
    goBuild windows arm64
}

main
