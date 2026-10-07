#!/usr/bin/env bash
#
# Opens the next snapshot version after a release.
#
# Run it once the release branch has been merged into master, from an up to date master. The bump is
# then made on a new bump/X_Y_Z branch, named after the coming version, and you merge that branch
# into master afterwards. Run from any other branch, such as a release branch that is not merged yet,
# the bump is made on that branch.
#
# It reads the released version from pom.xml, suggests the next snapshot version and lets you
# confirm it or enter another one, sets that version in pom.xml, commits and pushes the branch.
#
# See internal/release.md.
set -euo pipefail

# The version helpers, the remote and the main branch are the ones of the release script.
# shellcheck source=release.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release.sh"

# Prints the snapshot version that development continues on after the given release version.
next_snapshot_version() {
  echo "$(suggest_next_version "$1")-SNAPSHOT"
}

# Prints the message of the commit that opens the next snapshot version after the given release.
bump_commit_message() {
  echo "build: bump version after $1"
}

# Prints the branch the bump is made on. From master that is a new bump/X_Y_Z branch, named after the
# coming version, from any other branch it is that branch, which is then used as it is.
bump_branch_for() {
  local current_branch="$1" version="$2"
  if [ "$current_branch" = "$MAIN_BRANCH" ]; then
    echo "bump/${version//./_}"
  else
    echo "$current_branch"
  fi
}

# Succeeds unless the remote has commits on master that the local master lacks. If the remote cannot
# be reached the local master is used as it is.
main_is_up_to_date() {
  if ! git fetch --quiet "$REMOTE" "$MAIN_BRANCH" 2>/dev/null; then
    echo "Could not fetch $MAIN_BRANCH from $REMOTE, using the local $MAIN_BRANCH." >&2
    return 0
  fi
  git merge-base --is-ancestor "$REMOTE/$MAIN_BRANCH" "$MAIN_BRANCH"
}

# Prints the version in pom.xml.
pom_version() {
  mvn -q --no-transfer-progress -N -Dexpression=project.version -DforceStdout help:evaluate
}

main() {
  local repo_root
  repo_root="$(git rev-parse --show-toplevel)"
  cd "$repo_root"

  echo "== Next snapshot version =="

  # Nothing is changed until every check has passed.

  if [ -n "$(git status --porcelain)" ]; then
    echo "The working tree has changed or untracked files. Commit, stash or remove them first." >&2
    git status --short >&2
    exit 1
  fi

  local current_branch
  current_branch="$(git branch --show-current)"
  if [ -z "$current_branch" ]; then
    echo "No branch is checked out. Check out $MAIN_BRANCH, once the release branch is merged into it." >&2
    exit 1
  fi

  if [ "$current_branch" = "$MAIN_BRANCH" ] && ! main_is_up_to_date; then
    echo "$MAIN_BRANCH is behind $REMOTE/$MAIN_BRANCH. Pull it first, so the merged release is here." >&2
    exit 1
  fi

  local released_version
  if ! released_version="$(pom_version)" || [ -z "$released_version" ]; then
    echo "Could not read the version from pom.xml." >&2
    exit 1
  fi

  if [ "${released_version%-SNAPSHOT}" != "$released_version" ]; then
    echo "The version in pom.xml is already the snapshot $released_version. There is nothing to bump." >&2
    exit 1
  fi

  if ! is_valid_version "$released_version"; then
    echo "The version in pom.xml, '$released_version', is not a released version of the form X.Y.Z." >&2
    exit 1
  fi

  local suggested_version
  suggested_version="$(next_snapshot_version "$released_version")"
  echo "Released version: $released_version"
  echo "Suggested version: $suggested_version"
  read -r -p "Use this version? [Y/n/type another version]: " answer

  local version
  case "$answer" in
    ""|y|Y|yes|Yes|YES)
      version="${suggested_version%-SNAPSHOT}"
      ;;
    n|N|no|No|NO)
      read -r -p "Enter the version (X.Y.Z, -SNAPSHOT is added): " version
      ;;
    *)
      version="$answer"
      ;;
  esac
  version="${version%-SNAPSHOT}"

  if ! is_valid_version "$version"; then
    echo "'$version' is not a version of the form X.Y.Z." >&2
    exit 1
  fi

  local snapshot_version="${version}-SNAPSHOT" branch
  branch="$(bump_branch_for "$current_branch" "$version")"

  if [ "$branch" != "$current_branch" ] && ! branch_is_free "$branch"; then
    echo "The branch '$branch' already exists here or on $REMOTE. Remove it, or pick another version." >&2
    exit 1
  fi

  # The checks are done. From here on the repository is changed.

  if [ "$branch" != "$current_branch" ]; then
    echo "Creating the branch '$branch' from '$current_branch' ..."
    git checkout -b "$branch"
  else
    echo "Bumping on the current branch '$branch'."
  fi

  echo "Setting the version to $snapshot_version in pom.xml ..."
  mvn --no-transfer-progress versions:set -DnewVersion="$snapshot_version" -DgenerateBackupPoms=false

  git add -- pom.xml
  git commit -m "$(bump_commit_message "$released_version")"

  echo "Pushing '$branch' to $REMOTE ..."
  git push -u "$REMOTE" "$branch"

  echo
  echo "Done. '$branch' is now on $snapshot_version."
  echo
  echo "== What is left =="
  echo "Open a pull request from '$branch' into $MAIN_BRANCH and merge it."
  if [ "$branch" = "$current_branch" ]; then
    echo "If '$branch' holds the release commit that v$released_version points at, merge it with"
    echo "\"Create a merge commit\". The other two buttons, \"Squash and merge\" and \"Rebase and"
    echo "merge\", write new commits onto $MAIN_BRANCH, and GitHub would then not show v$released_version"
    echo "on $MAIN_BRANCH."
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
