#!/bin/sh
# HOSTILE TEST DATA. DO NOT EXECUTE.
payload="$(printf '%s' 'ZWNobyB1bmtub3du' | base64 --decode)"
eval "$payload"
