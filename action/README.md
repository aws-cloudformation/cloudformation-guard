# CloudFormation Guard Github Action [![Coverage](./badges/coverage.svg)](./badges/coverage.svg)

- [CloudFormation Guard Github Action ](#cloudformation-guard-github-action-)
  - [About](#about)
  - [Usage](#usage)
    - [Pull Request Example](#pull-request-example)
    - [Push Example](#push-example)
    - [Code Scanning \& Analysis Example](#code-scanning--analysis-example)
    - [Action Inputs](#action-inputs)
    - [Action Outputs](#action-outputs)
  - [Development](#development)
  - [Testing](#testing)
  - [Creating a release](#creating-a-release)

## About

The CloudFormation Guard GitHub Action validates AWS CloudFormation templates using your defined CloudFormation Guard rules. It is designed to be used as a part of your GitHub Actions CI workflow, allowing you to automatically validate your CloudFormation templates whenever changes are made to your repository.

This action ensures that your CloudFormation templates adhere to your defined CloudFormation Guard rules, providing continuous validation and feedback during the development process. It can help catch potential issues early and maintain consistency across your CloudFormation templates.

This action performs the following tasks:

1. **Checkout Repository**: If the `checkout` input is set to `true`, the action will checkout the repository before running the validation. This allows you to use this action as a standalone workflow without the necessity for actions/checkout.
2. **Validate CloudFormation Templates**: The action uses CloudFormation Guard to validate the CloudFormation templates specified by the `data` input against the rules specified by the `rules` input.
3. **Handle Validation Results**: Depending on the type of GitHub event (pull request or push), the action handles the validation results differently:
   - For pull request events, if the `create-review` input is set to `true`, the action will create a pull request review with comments along with output on the action summary for any validation failures within the pull requests changed files.
     - **NOTE:** The max results on list files for a pull request is 3000. If your pull requests tend to have more than 3000 files changed in them, you'll also want to depend on `push`.
   - For push events, the action will output the validation failures to the action summary.
4. **Upload Code Scan**: If the `analyze` input is set to `true`, the action will upload the validation results in the SARIF format to GitHub's code scanning dashboard.

## Usage

### Pull Request Example

```yaml
name: CloudFormation Guard Validate

on:
  pull_request:

jobs:
  guard:
    runs-on: ubuntu-latest
    name: CloudFormation Guard validate
    steps:
      - name: CloudFormation Guard validate
        uses: aws-cloudformation/cloudformation-guard@action-v0.0.1
        with:
          rules: './path/to/rules'
          data: './path/to/data'
          token: ${{ secrets.GITHUB_TOKEN }}
```

### Push Example

```yaml
name: CloudFormation Guard validate

on:
  push:

jobs:
  guard:
    runs-on: ubuntu-latest
    name: CloudFormation Guard validate
    steps:
      - name: CloudFormation Guard validate
        uses: aws-cloudformation/cloudformation-guard@action-v0.0.1
        with:
          rules: './path/to/rules'
          data: './path/to/data'
```

### Code Scanning & Analysis Example

```yaml
name: CloudFormation Guard Analysis

on:
  schedule:
    - cron: '45 15 * * 4'

jobs:
  guard:
    runs-on: ubuntu-latest
    name: CloudFormation Guard analyze
    steps:
      - name: CloudFormation Guard analyze
        uses: aws-cloudformation/cloudformation-guard@action-v0.0.1
        with:
          rules: './path/to/rules'
          data: './path/to/data'
          analyze: true
          token: ${{ secrets.GITHUB_TOKEN }}
```

### Action Inputs

The action accepts the following inputs:

| Name            | Description                                                                                                  | Default                   |
| --------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------- |
| `rules`         | Guard rules path relative to the root of the repository.                                                     | `.`                       |
| `data`          | Template data path relative to the root of the repository.                                                   | `.`                       |
| `token`         | GitHub token for API calls.                                                                                  | (optional for some usage) |
| `checkout`      | Checkout the repository if not using a composite action where CloudFormation Guard follows actions/checkout. | `true`                    |
| `analyze`       | Upload the SARIF report to GitHub's code scanning dashboard.                                                 | `false`                   |
| `create-review` | Create a pull request review with comments during pull request checks.                                       | `true`                    |

### Action Outputs

The action outputs the following:

| Name     | Description                                                          |
| -------- | -------------------------------------------------------------------- |
| `report` | A stringified SARIF report from the CloudFormation Guard validation. |

## Development

To install dependencies and watch for file changes run the following.

```shell
npm install
npm package:watch
```

To automatically fix formatting issues run the following.

```shell
npm run lint:fix
```

## Testing

To run tests against your changes run the following.

```shell
npm run test
```

## Creating a release

To create a new release with the latest bundle run the following and follow the prompts.

```shell
npm run package
# COMMIT THE CHANGED BUNDLE
npm run release
```
