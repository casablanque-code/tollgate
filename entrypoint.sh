#!/bin/sh
set -e

# Substitute env vars into config template → runtime config
envsubst < /app/config.template.yaml > /app/config.yaml

exec ./tollgate --config /app/config.yaml
