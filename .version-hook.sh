#!/bin/bash
if [ -z "$1" ]; then
  echo "Error: Version number required"
  exit 1
fi
NEW_VERSION="$1"

# Update version in Cargo.toml (single source of truth)
# cli.rs, main.rs, and codegen.rs use env!("CARGO_PKG_VERSION") at compile time
sed -i.bak "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml && rm Cargo.toml.bak

echo "Updated rshc to version $NEW_VERSION"
