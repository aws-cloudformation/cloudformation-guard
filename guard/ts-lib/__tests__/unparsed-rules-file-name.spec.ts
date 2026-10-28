import * as path from 'path';
import { describe, expect, it, jest } from '@jest/globals';

// The document the core writes in payload mode (the only mode this module uses) when the one rules
// file it was given does not parse, as measured with `cfn-guard validate --payload -o sarif -z -S none`:
// no results, one failed invocation, and the rules file known only as RULES_STDIN[1]. The core is
// replaced here so that the name rewriting is tested against this document whatever wasm build is
// committed.
const unparsedRulesDocument = {
  $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'cfn-guard',
          semanticVersion: '3.2.0',
          fullName: 'cfn-guard 3.2.0',
          organization: 'Amazon Web Services',
          downloadUri: 'https://github.com/aws-cloudformation/cloudformation-guard',
          informationUri: 'https://github.com/aws-cloudformation/cloudformation-guard',
          shortDescription: { text: 'AWS CloudFormation Guard' },
        },
      },
      invocations: [
        {
          executionSuccessful: false,
          toolConfigurationNotifications: [
            {
              level: 'error',
              message: {
                text: 'Rules file RULES_STDIN[1] could not be parsed, so none of its rules were evaluated: Parser Error when parsing `Parsing Error Error parsing file RULES_STDIN[1] at line 1 at column 40, when handling expecting either a property access "engine.core" or value like "string" or ["this", "that"], fragment  }\n`',
              },
            },
          ],
        },
      ],
      artifacts: [],
      results: [],
    },
  ],
};

jest.doMock('../guard', () => ({
  OutputFormatType: { Sarif: 4 },
  ShowSummaryType: { None: 4 },
  ValidateBuilder: class {
    payload() {
      return this;
    }
    structured() {
      return this;
    }
    showSummary() {
      return this;
    }
    outputFormat() {
      return this;
    }
    // The wasm returns the document as a JSON string, which formatOutput parses.
    tryBuildAndExecute() {
      return JSON.stringify(unparsedRulesDocument);
    }
  },
}));

describe('validate on a rules file that does not parse', () => {
  it('should name the rules file, not RULES_STDIN[n], in the failed invocation', async () => {
    const { validate } = await import('../index.js');
    const rulesPath = path.resolve(__dirname, './__fixtures__/malformed-rules/missing-operand.guard');

    const result = await validate({
      rulesPath,
      dataPath: path.resolve(__dirname, './__fixtures__/data-dir'),
    });

    // validate writes a file name with `/` as the separator on every platform, as it does for the
    // data file names, so the expected name is the resolved path with any `\` turned into `/`.
    const expectedName = rulesPath.split('\\').join('/');

    const [invocation] = result.runs[0].invocations ?? [];
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolConfigurationNotifications?.[0].message.text).toBe(
      `Rules file ${expectedName} could not be parsed, so none of its rules were evaluated: Parser Error when parsing \`Parsing Error Error parsing file ${expectedName} at line 1 at column 40, when handling expecting either a property access "engine.core" or value like "string" or ["this", "that"], fragment  }\n\``
    );
    expect(JSON.stringify(result)).not.toContain('RULES_STDIN');
  });
});
