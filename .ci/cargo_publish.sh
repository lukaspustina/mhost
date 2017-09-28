// Remove all remaining, untracked files
git clean -f -x
cross publish --token "$1"

