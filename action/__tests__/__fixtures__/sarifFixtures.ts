import { SarifReport, SarifRun } from 'cfn-guard';

export const sarifRunFixture: SarifRun = {
  tool: {
    driver: {
      name: 'cfn-guard',
      semanticVersion: '3.1.1',
      fullName: 'cfn-guard 3.1.1',
      organization: 'Amazon Web Services',
      downloadUri: 'https://github.com/aws-cloudformation/cloudformation-guard',
      informationUri:
        'https://github.com/aws-cloudformation/cloudformation-guard',
      shortDescription: {
        text: 'AWS CloudFormation Guard is an open-source general-purpose policy-as-code evaluation tool. It provides developers with a simple-to-use, yet powerful and expressive domain-specific language (DSL) to define policies and enables developers to validate JSON- or YAML- formatted structured data with those policies.'
      }
    }
  },
  artifacts: [
    {
      location: {
        uri: 'some/path'
      }
    }
  ],
  results: [
    {
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: 'file1.yaml'
            },
            region: {
              startLine: 10,
              startColumn: 5
            }
          }
        }
      ],
      message: {
        text: 'Violation message 1'
      },
      level: 'error',
      ruleId: 'rule1'
    },
    {
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: 'file2.yaml'
            },
            region: {
              startLine: 15,
              startColumn: 8
            }
          }
        }
      ],
      level: 'error',
      message: {
        text: 'Violation message 2'
      },
      ruleId: 'rule2'
    }
  ]
};

export const sarifResultFixture: SarifReport = {
  $schema: 'x',
  version: '2.1.0',
  runs: [sarifRunFixture]
};

// The shape the current core emits for a finding whose position it does not
// know: no `region` at all, or a `region` with a `startLine` and no
// `startColumn`. SARIF requires neither member.
export const sarifRunFixtureWithoutRegion: SarifRun = {
  tool: sarifRunFixture.tool,
  artifacts: sarifRunFixture.artifacts,
  results: [
    {
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: 'file1.yaml'
            }
          }
        }
      ],
      message: {
        text: 'Violation message 1'
      },
      level: 'error',
      ruleId: 'rule1'
    },
    {
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: 'file2.yaml'
            },
            region: {
              startLine: 15
            }
          }
        }
      ],
      level: 'error',
      message: {
        text: 'Violation message 2'
      },
      ruleId: 'rule2'
    }
  ]
};

// What the library returns for `rulesPath: 'rules/missing-operand.guard'`
// whose content is `rule r { Resources.*.Properties.Size <= }`: the core's
// text with its RULES_STDIN[1] placeholder rewritten to the rules path.
export const unparsedRulesFileNotificationText =
  'Rules file rules/missing-operand.guard could not be parsed, so none of its rules were evaluated: Parser Error when parsing `Parsing Error Error parsing file rules/missing-operand.guard at line 1 at column 40, when handling expecting either a property access "engine.core" or value like "string" or ["this", "that"], fragment  }\n`';

// The shape the current core emits when a rules file did not parse: no
// results, because nothing was evaluated, and one failed invocation that says
// why.
export const sarifResultFixtureUnparsedRules: SarifReport = {
  $schema: 'x',
  version: '2.1.0',
  runs: [
    {
      tool: sarifRunFixture.tool,
      invocations: [
        {
          executionSuccessful: false,
          toolConfigurationNotifications: [
            {
              level: 'error',
              message: {
                text: unparsedRulesFileNotificationText
              }
            }
          ]
        }
      ],
      artifacts: [],
      results: []
    }
  ]
};

// One rules file did not parse while the others found violations: the run
// carries both the failed invocation and the results.
export const sarifResultFixtureMixed: SarifReport = {
  $schema: 'x',
  version: '2.1.0',
  runs: [
    {
      ...sarifRunFixture,
      invocations: sarifResultFixtureUnparsedRules.runs[0].invocations
    }
  ]
};
