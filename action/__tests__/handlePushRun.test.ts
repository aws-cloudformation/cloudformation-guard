import { describe, it, expect } from '@jest/globals'
import { handlePushRun } from '../src/handlePushRun'

describe('handlePushRun', () => {
  it('should return an array of violation details', async () => {
    const mockRun = {
      results: [
        {
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: '/path/to/file.ts'
                },
                region: {
                  startLine: 10,
                  startColumn: 5
                }
              }
            }
          ],
          ruleId: 'rule-id-1',
          message: {
            text: 'Violation message'
          }
        }
      ]
    }

    // @ts-ignore doesn't need to be a real run
    const violations = await handlePushRun({ run: mockRun })

    expect(violations).toEqual([
      ['❌ /path/to/file.ts:L10,C5', 'Violation message', 'rule-id-1']
    ])
  })
})
