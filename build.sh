#!/bin/bash

echo "start build"

# 构建三个可执行程序
go build -o bin/dnsdiff ./cmd/dnsdiff
echo "dnsdiff build finished"
go build -o bin/dnsreplay ./cmd/dnsreplay
echo "dnsreplay build finished"
go build -o bin/dnscmp ./cmd/dnscmp
echo "dnscmp build finished"
go build -o bin/formcheck ./cmd/formcheck
echo "formcheck build finished"

echo "build end"

