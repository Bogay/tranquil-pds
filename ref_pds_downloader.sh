git clone --depth 1 --filter=blob:none --sparse https://github.com/bluesky-social/atproto.git reference-pds

cd reference-pds

git sparse-checkout set packages/pds

git checkout main

mv packages/pds/* .
mv packages/pds/.[!.]* . 2>/dev/null
rm -rf .git
