# XrayR
XrayR 

go get github.com/xtls/xray-core@0a8470cb14ebbf7ee4cbb6c601bb9db072ace985

go mod tidy

$env:CGO_ENABLED=0
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o XrayR -ldflags "-s -w"

