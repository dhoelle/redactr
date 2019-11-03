#!/bin/bash
# usage: ./bump.sh <major|minor|patch>

# must specify 'major', 'minor', or 'patch'
BUMP=$1
if [ "$BUMP" != "major" ] && \
   [ "$BUMP" != "minor" ] && \
   [ "$BUMP" != "patch" ]; then
    echo "usage: $0 <major|minor|patch>"
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "there are uncommitted git changes, will not bump";
  exit 1
fi

# only run on master branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "${CURRENT_BRANCH}" != "master" ]; then
    cleanup() {
        git checkout $CURRENT_BRANCH
    }
    trap cleanup EXIT
    git checkout master
fi

DESCRIBE=$(git describe)
if [ ! $? -eq 0 ]; then
    CURRENT=0.0.0
    CMAJOR=0
    CMINOR=0
    CPATCH=0
else
    CURRENT=$(echo $DESCRIBE | cut -d'-' -f1 | cut -c2-)
    CMAJOR=$(echo $CURRENT | cut -d'.' -f1)
    CMINOR=$(echo $CURRENT | cut -d'.' -f2)
    CPATCH=$(echo $CURRENT | cut -d'.' -f3)
fi
echo "current version: ${CURRENT}"

case "$BUMP" in
    major)
        NMAJOR=$((CMAJOR + 1))
        NMINOR=0
        NPATCH=0
        ;;
    minor)
        NMAJOR=$CMAJOR
        NMINOR=$((CMINOR + 1))
        NPATCH=0
        ;;
    patch)
        NMAJOR=$CMAJOR
        NMINOR=$CMINOR
        NPATCH=$((CPATCH + 1))
        ;;
esac
NEXT="${NMAJOR}.${NMINOR}.${NPATCH}"
echo "   next version: ${NEXT}"

echo -n "git tag ${NEXT} and push (y/n)? "
read answer
if [ "$answer" = "${answer#[Yy]}" ] ;then
    echo "aborting, no tags were created"
    exit 1
fi

git tag -a v${NEXT} -m "Version ${NEXT}"
git push --tags
if [ ! $? -eq 0 ]; then
    echo "git push --tags failed. Fix the issue, then manually run `git push --tags`"
    exit 1
fi
echo "git tag ${NEXT} pushed"
