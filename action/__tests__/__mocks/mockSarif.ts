import { SarifReport, SarifRun } from 'cfn-guard'

export const mockSarifRun: SarifRun = {
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
}

export const mockSarifResult: SarifReport = {
  $schema: 'x',
  version: '2.1.0',
  runs: [mockSarifRun]
}
