#!/bin/bash
echo "Downloading haileyok/cocoon"
git clone --depth 1 https://github.com/haileyok/cocoon reference-pds-hailey
rm -rf reference-pds-hailey/.git
echo "Downloading bluesky-social/atproto pds package"
mkdir reference-pds-bsky
cd reference-pds-bsky
git init
git remote add origin https://github.com/bluesky-social/atproto.git
git config core.sparseCheckout true
echo "packages/pds" >> .git/info/sparse-checkout
git pull --depth 1 origin main
mv packages/pds/* .
rm -rf packages .git
cd ..
echo "Downloads complete!"
