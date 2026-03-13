#!/bin/bash
if [ -z "$1" ]; then
  echo "Error: Version number required"
  exit 1
fi
NEW_VERSION="$1"

# Update version in Cargo.toml
sed -i.bak "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml && rm Cargo.toml.bak

# Update version in cli.rs
sed -i.bak "s/version = \".*\"/version = \"$NEW_VERSION\"/" src/cli.rs && rm src/cli.rs.bak

# Update version strings in main.rs
sed -i.bak "s/rshc Version [0-9]*\.[0-9]*\.[0-9]*/rshc Version $NEW_VERSION/g" src/main.rs && rm src/main.rs.bak
sed -i.bak "s/rshc Version [0-9]*\.[0-9]*\.[0-9]*/rshc Version $NEW_VERSION/g" src/codegen.rs && rm src/codegen.rs.bak

echo "Updated rshc to version $NEW_VERSION"
