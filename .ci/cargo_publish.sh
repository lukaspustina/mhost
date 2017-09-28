#!/bin/sh

echo "Cleaning working directory"
git clean -f -x
echo "Publishing to crates.io"
cross publish --token "$1"

