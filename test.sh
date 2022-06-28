#!/bin/bash

set -v
set -e
export PATH=$PATH:/usr/local/go/bin
go build
echo acsa1411|sudo -S mv webhook /usr/local/bin/
echo acsa1411|sudo -S systemctl restart webhook.service