#!/usr/bin/env bash
#
# Runs a release, on a branch, up to and including the release tag.
#
# The script works out the next version from the tags that exist, lets you confirm it or enter
# another one, sets that version in pom.xml, builds the project, builds the javadoc and copies it to
# docs/javadoc, commits, pushes the branch, tags the release commit and pushes the tag. Merging the
# branch into master is left to you, and the next snapshot version is opened afterwards with
# internal/post-release-bump.sh, run on master.
#
# Run from master, the release is made on a new release/X_Y_Z branch. Run from any other branch, the
# release is made on that branch.
#
# Pushing the tag is what starts publishing, so the script asks before it does that. Publishing to
# Maven Central and creating the GitHub release is done by GitHub workflows when the tag is pushed,
# see internal/release.md.
set -euo pipefail

REMOTE="origin"
MAIN_BRANCH="master"
WORKFLOW_URL="https://github.com/swedenconnect/opensaml-security-ext/actions/workflows/maven-central-deploy.yml"

# The directory, published by GitHub Pages, that holds the javadoc of the latest release.
JAVADOC_DIR="docs/javadoc"

# Where the Maven javadoc plugin writes the javadoc.
JAVADOC_BUILD_DIR="target/reports/apidocs"

# Prints the version that follows the given tag or version: the last number raised by one.
suggest_next_version() {
  local version="${1#v}" major minor patch
  major="$(echo "$version" | cut -d. -f1)"
  minor="$(echo "$version" | cut -d. -f2)"
  patch="$(echo "$version" | cut -d. -f3)"
  echo "${major}.${minor}.$((patch + 1))"
}

# Succeeds if the given version is three numbers separated by dots.
is_valid_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# Prints the message of the commit that holds the given release version.
release_commit_message() {
  echo "build: $1 release"
}

# Prints the branch the release is made on. From master that is a new release/X_Y_Z branch, from any
# other branch it is that branch, which is then used as it is.
release_branch_for() {
  local current_branch="$1" version="$2"
  if [ "$current_branch" = "$MAIN_BRANCH" ]; then
    echo "release/${version//./_}"
  else
    echo "$current_branch"
  fi
}

# Succeeds if no branch of that name exists, neither here nor on the remote.
branch_is_free() {
  ! git show-ref --verify --quiet "refs/heads/$1" &&
    ! git ls-remote --exit-code --heads "$REMOTE" "$1" >/dev/null 2>&1
}

# Succeeds if no tag of that name exists, neither here nor on the remote.
tag_is_free() {
  ! git show-ref --verify --quiet "refs/tags/$1" &&
    ! git ls-remote --exit-code --tags "$REMOTE" "$1" >/dev/null 2>&1
}

# Builds the javadoc with the settings of the release profile and replaces the contents of
# docs/javadoc with it. The "latest" directory in docs/javadoc is kept, since it is not part of the
# generated javadoc.
update_javadoc() {
  mvn --no-transfer-progress -Prelease javadoc:javadoc

  if [ ! -f "$JAVADOC_BUILD_DIR/index.html" ]; then
    echo "The javadoc build left no $JAVADOC_BUILD_DIR/index.html." >&2
    exit 1
  fi

  find "$JAVADOC_DIR" -mindepth 1 -maxdepth 1 ! -name latest -exec rm -rf {} +
  cp -R "$JAVADOC_BUILD_DIR/." "$JAVADOC_DIR/"
}

main() {
  local repo_root
  repo_root="$(git rev-parse --show-toplevel)"
  cd "$repo_root"

  echo "== Release =="

  # From here down to the branch is created, nothing is changed. Every check that can stop the
  # release runs first, so a release that cannot go through leaves the repository as it was.

  if [ -n "$(git status --porcelain)" ]; then
    echo "The working tree has changed or untracked files. Commit, stash or remove them first." >&2
    git status --short >&2
    exit 1
  fi

  local current_branch
  current_branch="$(git branch --show-current)"
  if [ -z "$current_branch" ]; then
    echo "No branch is checked out. Check out $MAIN_BRANCH, or the branch you want to release from." >&2
    exit 1
  fi

  echo "Fetching tags from $REMOTE ..."
  git fetch --tags --quiet "$REMOTE" || echo "Could not fetch tags from $REMOTE, using the local tags."

  local latest_tag suggested_version
  # Only vX.Y.Z tags count. The pattern of git tag -l would also let through a tag such as v1.0.0-RC1.
  # Releases before the move to v-prefixed tags were tagged X.Y.Z, so those count too.
  latest_tag="$(git tag -l | grep -E '^v?[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' | sort -V | tail -1 || true)"

  if [ -z "$latest_tag" ]; then
    echo "There is no tag of the form vX.Y.Z."
    read -r -p "Enter the first version (X.Y.Z): " suggested_version
  else
    suggested_version="$(suggest_next_version "$latest_tag")"
    echo "Latest released version: $latest_tag"
  fi

  echo "Suggested version: $suggested_version"
  read -r -p "Use this version? [Y/n/type another version]: " answer

  local version
  case "$answer" in
    ""|y|Y|yes|Yes|YES)
      version="$suggested_version"
      ;;
    n|N|no|No|NO)
      read -r -p "Enter the version (X.Y.Z): " version
      ;;
    *)
      version="$answer"
      ;;
  esac

  if ! is_valid_version "$version"; then
    echo "'$version' is not a version of the form X.Y.Z." >&2
    exit 1
  fi

  local branch tag
  branch="$(release_branch_for "$current_branch" "$version")"
  tag="v$version"

  if [ "$branch" != "$current_branch" ] && ! branch_is_free "$branch"; then
    echo "The branch '$branch' already exists here or on $REMOTE. Remove it, or pick another version." >&2
    exit 1
  fi

  if ! tag_is_free "$tag" || ! tag_is_free "$version"; then
    echo "A tag for version $version already exists here or on $REMOTE. Version $version has been released." >&2
    exit 1
  fi

  # The checks are done. From here on the repository is changed.

  if [ "$branch" != "$current_branch" ]; then
    echo "Creating the branch '$branch' from '$current_branch' ..."
    git checkout -b "$branch"
  else
    echo "Releasing on the current branch '$branch'."
  fi

  echo "Setting the version to $version in pom.xml ..."
  mvn --no-transfer-progress versions:set -DnewVersion="$version" -DgenerateBackupPoms=false

  echo "Building the project ..."
  mvn --no-transfer-progress clean install

  echo "Building the javadoc and copying it to $JAVADOC_DIR ..."
  update_javadoc

  git add -- pom.xml
  git add -A -- "$JAVADOC_DIR"
  git commit -m "$(release_commit_message "$version")"

  echo "Pushing '$branch' to $REMOTE ..."
  git push -u "$REMOTE" "$branch"

  echo
  echo "== Tagging =="
  echo "Pushing the tag $tag starts publishing. The artifacts go to Maven Central and a GitHub"
  echo "release is created. A version that has been published cannot be removed or replaced."
  read -r -p "Create the tag $tag and push it? [y/N]: " tag_answer

  case "$tag_answer" in
    y|Y|yes|Yes|YES)
      ;;
    *)
      echo
      echo "Stopped before tagging."
      echo "The branch '$branch' is pushed to $REMOTE and holds version $version."
      echo "There is no tag and nothing has been published."
      echo "To tag later, from that commit:"
      echo
      echo "    git tag -a $tag -m \"Version $version\""
      echo "    git push $REMOTE $tag"
      echo
      echo "Then merge '$branch' into $MAIN_BRANCH and run internal/post-release-bump.sh on $MAIN_BRANCH."
      exit 0
      ;;
  esac

  echo "Tagging $tag and pushing it ..."
  git tag -a "$tag" -m "Version $version"
  git push "$REMOTE" "$tag"

  echo
  echo "== Publishing =="
  echo "The tag started the Maven Central workflow and the GitHub release workflow. Follow the"
  echo "Maven Central run here:"
  echo
  echo "    $WORKFLOW_URL"
  echo
  echo "It publishes nothing unless the version in pom.xml is $version."

  echo
  echo "Done. Version $version is tagged as $tag on '$branch'."
  echo
  echo "== What is left =="
  echo "1. Check that the Maven Central workflow for $tag succeeded."
  echo
  echo "2. Open a pull request from '$branch' into $MAIN_BRANCH and merge it with \"Create a merge"
  echo "   commit\". The other two buttons, \"Squash and merge\" and \"Rebase and merge\", write new"
  echo "   commits onto $MAIN_BRANCH. The commit that $tag points at would then not be part of the"
  echo "   history of $MAIN_BRANCH, and GitHub would not show $tag on $MAIN_BRANCH."
  echo
  echo "3. Once it is merged, open the next snapshot version from an up to date $MAIN_BRANCH:"
  echo
  echo "       git checkout $MAIN_BRANCH && git pull"
  echo "       internal/post-release-bump.sh"
  echo
  echo "   It makes the bump on a new branch, which you then merge into $MAIN_BRANCH."
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
