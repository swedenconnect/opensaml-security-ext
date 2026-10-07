# Releasing

How to make a release of opensaml-security-ext.

This is for maintainers. Only maintainers can create release tags.

## How a release works

A release is made in three steps:

1. [`internal/release.sh`](release.sh) sets the release version on a release branch, builds it,
   updates the javadoc in `docs/javadoc`, commits it, pushes the branch, and puts the tag `vX.Y.Z`
   on the release commit. Pushing that tag is what starts publishing.
2. You merge the release branch into `master`, through a pull request.
3. [`internal/post-release-bump.sh`](post-release-bump.sh), run on an up to date `master`, opens the
   next snapshot version on a new branch, which you then merge into `master` too.

The tag is created before the branch is merged, so the tag does not sit on a commit on `master` at
the time it is made. That is fine. The tag keeps the released commit available whatever happens to
the branch.

## Before you start

- The working tree has no changes and no untracked files.
- You can push to `origin`.
- Maven works on your machine.

## Run the release script

From the root of the repository:

```bash
./internal/release.sh
```

It does the release up to and including the tag, in one run:

1. Checks that the working tree is clean and that a branch is checked out.
2. Fetches the tags from `origin`, takes the newest release tag and suggests the next version,
   which is the last number raised by one. Both `vX.Y.Z` tags and the older `X.Y.Z` tags count. You
   confirm the suggestion, or type another version.
3. Works out which branch to use. From `master` that is a new branch named `release/X_Y_Z`, so
   version 4.2.2 is released on `release/4_2_2`. From any other branch the release is made on that
   branch.
4. Checks that the version is of the form X.Y.Z, that the branch does not exist yet, here or on
   `origin`, and that no tag for the version exists either. If a check fails the script stops and
   the repository is exactly as it was.
5. Creates the release branch, if it is making one.
6. Sets the version in `pom.xml` with `mvn versions:set`.
7. Builds and tests with `mvn clean install`.
8. Builds the javadoc with `mvn -Prelease javadoc:javadoc`, so that the titles carry the release
   version, and replaces the contents of `docs/javadoc` with it. The `docs/javadoc/latest` directory
   is kept.
9. Commits `pom.xml` and `docs/javadoc` as `build: X.Y.Z release`, and pushes the branch to
   `origin`.
10. Asks whether to create the tag and push it. If you say no the script stops here. The branch is
    pushed, there is no tag, and nothing is published. It prints the two commands you need to tag
    later.
11. Creates the annotated tag `vX.Y.Z` on the release commit and pushes that one tag. This starts
    the Maven Central workflow
    ([`maven-central-deploy.yml`](../.github/workflows/maven-central-deploy.yml)) and the GitHub
    release workflow ([`github-release.yml`](../.github/workflows/github-release.yml)).
12. Tells you to open a pull request from the branch into `master`, and to run
    `internal/post-release-bump.sh` on `master` once it is merged.

Only the new tag is pushed, with `git push origin vX.Y.Z`. Nothing pushes all tags, so a tag you
happen to have locally cannot start a release workflow by accident.

The javadoc in `docs/javadoc` is published by GitHub Pages from `master`, so it goes live once the
release branch is merged.

## Run the post-release bump script

Once the release branch is merged into `master`, from the root of the repository:

```bash
git checkout master
git pull
./internal/post-release-bump.sh
```

1. Checks that the working tree is clean and that a branch is checked out. On `master` it also
   checks that `master` is not behind `origin/master`, so that the merged release is there.
2. Checks that the version in `pom.xml` is a release version of the form X.Y.Z and not a snapshot.
3. Suggests the next snapshot version, the released version with the last number raised by one
   and `-SNAPSHOT` added. You confirm it, or type another version as X.Y.Z.
4. From `master` it creates a new branch named `bump/X_Y_Z` after the coming version.
5. Sets the version in `pom.xml`, commits it as `build: bump version after X.Y.Z` and pushes the
   branch.

Then open a pull request from the bump branch into `master` and merge it. The bump branch holds no
tagged commit, so any of the merge buttons will do.

## Merge the release pull request with "Create a merge commit"

"Squash and merge" and "Rebase and merge" write new commits onto `master`. The commit the tag points
at is then not part of the history of `master`, and GitHub does not show the tag on `master`.

## Rules for tags

1. **Start with `v`.** Version `4.2.2` is tagged `v4.2.2`. Releases up to 4.2.1 were tagged without
   the `v`, and those tags do not start any workflow.
2. **Use an annotated tag.** The script does this for you.
3. **The version in `pom.xml` must match the tag.** The Maven Central workflow stops if it does
   not, or if the version is still a snapshot.
4. **Never move or delete a tag that has been pushed.** If a tag is wrong, release a new version.
5. **Never release the same version twice.** Maven Central does not let a published version be
   changed or taken down.

## Publishing to Maven Central

The Maven Central workflow builds the tagged commit with `mvn -Prelease clean deploy`, tests
included, signs every file with the Bouncy Castle signer of the Maven GPG plugin
(`-Dgpg.signer=bc`), and uploads them to Central. `autoPublish` is on, so an upload that passes
Central's checks goes live without anything done in the Central portal.

It uses these organisation secrets: `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_TOKEN_PASSWORD`,
`BOT_GPG_PRIVATE_KEY` and `BOT_GPG_PASSWORD`.

To build everything the release would upload, without signing or uploading:

```bash
mvn -Prelease -Dgpg.skip=true clean verify
```

## If something goes wrong

- **The build failed during the release script.** Fix the problem on the release branch and commit
  it. Then start the script again on that branch, which uses it as it is.
- **The script stopped before the tag.** The branch is on `origin` and holds the release version.
  To finish, from the release commit:

  ```bash
  git tag -a vX.Y.Z -m "Version X.Y.Z"
  git push origin vX.Y.Z
  ```

- **The GitHub release workflow failed.** Run it again, or create the release by hand from the tag.
- **The Maven Central workflow failed.** If the version check, the build or the tests failed,
  nothing was uploaded. If the upload failed Central's checks, nothing went live. In both cases fix
  the cause and release a new version rather than moving the tag.
