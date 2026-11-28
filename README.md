# StackRails CI checks

The StackRails governance check for your own CI: GitHub Actions, GitLab CI, Bitbucket Pipelines and plain git
servers. StackRails holds no write permission on your repositories; your CI sends the change with a service key and
posts the verdict itself.

Setup for every host: [`ci/README.md`](ci/README.md). Pin a release tag, never `main`.

This repository is published from StackRails releases; changes made here are overwritten.

Licensed under the Apache License, Version 2.0: see [`LICENSE`](LICENSE).
