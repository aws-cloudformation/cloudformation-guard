# AWS CloudFormation Guard Typescript / Javascript Module

Currently the module supports only the validate functionality of cfn-guard and only outputs to SARIF format.

## Install

```shell
npm install @aws/cloudformation-guard
```

## How to use

```typescript
import { validate } from "@aws/cloudformation-guard"

(async () => {
  const result = await validate({
    rulesPath: "path/to/rules",
    dataPath: "path/to/data",
  })

  console.log(result)
})()
```
