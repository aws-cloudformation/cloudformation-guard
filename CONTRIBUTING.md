# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.


## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment


## Contributing via Pull Requests
Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Ensure local tests pass.
4. If you changed Rust dependencies, regenerate the ATTRIBUTION file:
   ```
   cargo install cargo-about
   cargo about generate about.hbs > ATTRIBUTION
   ```
5. Commit to your fork using clear commit messages that follow [Conventional Commits](#commit-messages).
6. Send us a pull request, answering any default questions in the pull request interface.
7. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.
8. If your pull request includes rules for the Examples, please review the [Examples README](guard-examples/README.md) for the acceptance criteria.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Commit messages

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/): a type, an
optional scope, then a short description.

```
fix: prevent silent policy enforcement failures
fix(deps): update undici to 6.28.0
feat: add a --structured flag to validate
chore: bump version to 3.2.1
```

The accepted types are `build`, `bump`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`,
`style` and `test`. A scope in parentheses is optional, as in `fix(deps):`. A `!` before the colon, as in
`feat!:`, marks a breaking change. Version bumps in this repository have used `chore:` rather than `bump:`.

**Pull requests are squash-merged, so the pull request title becomes the commit message on `main`.** That title
is what CI checks; the individual commits on your branch are not checked, so you are free to commit however
suits you while you work.

[commitizen](https://commitizen-tools.github.io/commitizen/) is configured to help with both writing and
checking messages:

```bash
pip install -r requirements-dev.txt

cz commit          # prompts for type, scope and description, then commits
cz check --rev-range origin/main..HEAD    # check what you have written so far
```

To have your messages checked as you commit, install the git hooks once:

```bash
pre-commit install
```

If you installed the hooks before commitizen was added, run `pre-commit install` again — the message check runs
at the `commit-msg` stage, which is a hook type that has to be installed separately from the others.

Version numbers and tags are not managed by commitizen; `.github/workflows/release.yml` owns those. `cz bump
--dry-run` is still a convenient way to see which version the commits since the last release imply.


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.


## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.


## Security issue notifications
If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.


## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

We may ask you to sign a [Contributor License Agreement (CLA)](http://en.wikipedia.org/wiki/Contributor_License_Agreement) for larger changes.
