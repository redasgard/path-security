#!/bin/bash
# Script to run cargo commands without proxy interference

unset http_proxy
unset https_proxy
unset HTTP_PROXY
unset HTTPS_PROXY

exec cargo "$@"

