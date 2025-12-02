#!/bin/bash

echo "start build"

# 构建三个可执行程序
go build -o dnsdiff ./cmd/dnsdiff
echo "dnsdiff build finished"
go build -o dnsreplay ./cmd/dnsreplay
echo "dnsreplay build finished"
go build -o dnscmp ./cmd/dnscmp
echo "dnscmp build finished"

echo "build end"

