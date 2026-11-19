# AWS CloudFormation Guard

TypeScript and JavaScript bindings for [AWS CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard), a policy-as-code tool for validating JSON and YAML data against Guard rules.

The package runs Guard in Node.js through a bundled WebAssembly build. You do not need to install the Guard CLI separately.

> **Current limitation:** the package exposes only validation, and results are returned only as [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

## Requirements

- Node.js 20 or later

## Installation

```shell
npm install @aws/cloudformation-guard
```

## Usage

```typescript
import { validate } from '@aws/cloudformation-guard';

async function main(): Promise<void> {
  try {
    const report = await validate({
      rulesPath: './rules',
      dataPath: './templates',
    });

    const results = report.runs[0]?.results ?? [];

    for (const result of results) {
      const location = result.locations[0]?.physicalLocation;
      console.log(
        `${result.ruleId}: ${result.message.text}` +
          (location
            ? ` (${location.artifactLocation.uri}:${location.region.startLine})`
            : '')
      );
    }

    if (results.length > 0) {
      process.exitCode = 1;
    }
  } catch (error) {
    console.error('Guard validation failed to run:', error);
    process.exitCode = 1;
  }
}

main();
```

## API

### `validate({ rulesPath, dataPath })`

Evaluates Guard rules against data files and returns a SARIF report.

```typescript
validate(params: { rulesPath: string; dataPath: string }): Promise<SarifReport>
```

| Parameter   | Type     | Description                                                       |
| ----------- | -------- | ----------------------------------------------------------------- |
| `rulesPath` | `string` | Path to a rules file, or to a directory scanned recursively.      |
| `dataPath`  | `string` | Path to a data file, or to a directory scanned recursively.       |

Supported file extensions:

| Input | Extensions                                         |
| ----- | -------------------------------------------------- |
| Rules | `.guard`, `.ruleset`                               |
| Data  | `.yaml`, `.yml`, `.json`, `.jsn`, `.template`      |

File handling:

- When a path names a file with an unsupported extension, the returned promise rejects with an error.
- When a path names a directory, files with unsupported extensions are ignored.

**Returns:** `Promise<SarifReport>`. Each result in `runs[0].results` describes a rule violation, with its rule ID, message, level, and the location in the data file. The `SarifReport` type and its related types are exported from the package's type definitions.

## Writing rules

- [CloudFormation Guard repository](https://github.com/aws-cloudformation/cloudformation-guard)
- [Clauses](https://github.com/aws-cloudformation/cloudformation-guard/blob/main/docs/CLAUSES.md)
- [Query and filtering](https://github.com/aws-cloudformation/cloudformation-guard/blob/main/docs/QUERY_AND_FILTERING.md)
- [Complex composition](https://github.com/aws-cloudformation/cloudformation-guard/blob/main/docs/COMPLEX_COMPOSITION.md)
- [Built-in functions](https://github.com/aws-cloudformation/cloudformation-guard/blob/main/docs/FUNCTIONS.md)
- [All Guard documentation](https://github.com/aws-cloudformation/cloudformation-guard/tree/main/docs)

## License

This project is licensed under the [Apache-2.0 License](https://github.com/aws-cloudformation/cloudformation-guard/blob/main/LICENSE).
