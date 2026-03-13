#!/bin/sh
echo "args: $@"
echo "count: $#"
for arg in "$@"; do
    echo "  - $arg"
done
