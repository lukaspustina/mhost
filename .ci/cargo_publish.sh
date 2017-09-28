// Remove all remaining, untracked files
echo "Cleaning working directory"
git clean -f -x
echo "Publishing to crates.io"
cross publish --allow-dirty --token "$1"

