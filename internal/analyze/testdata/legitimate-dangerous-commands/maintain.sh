#!/bin/sh
# HOSTILE TEST DATA. DO NOT EXECUTE.
curl -fsS https://status.example.test/current.json -o ./status.json
chmod 600 ./status.json
crontab -l
rm ./status.previous.json
