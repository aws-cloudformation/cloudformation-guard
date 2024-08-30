# AWS CloudFormation Guard Typescript / Javascript Module

Currently the module supports only the validate functionality of cfn-guard and only outputs to SARIF format.

## Install

```shell
npm install 'https://gitpkg.now.sh/aws-cloudformation/cloudformation-guard/guard/ts-lib?33d9931'
```

## How to use

```typescript
import { validate } from "cfn-guard"

(async () => {
  const result = await validate({
    rulesPath: "path/to/rules",
    dataPath: "path/to/data",
  })

  console.log(result)
})()
```
