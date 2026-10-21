import { validate } from '../index.js'
import { sanitizeSarifOutput } from '../utils';
import * as path from 'path';
import { describe, expect, it } from '@jest/globals';

describe('validate', () => {
  it('should handle directories in both rules, data, and match the snapshot', async () => {
    const result = await validate({
      rulesPath: path.resolve(__dirname, '../../resources/validate/rules-dir'),
      dataPath: path.resolve(__dirname, '../../resources/validate/data-dir'),
    })

    expect(sanitizeSarifOutput(result)).toMatchSnapshot()
  })
  it('should handle a directory in rules, a single data file, and match the snapshot', async () => {
    const result = await validate({
      rulesPath: path.resolve(__dirname, '../../resources/validate/rules-dir'),
      dataPath: path.resolve(__dirname, '../../resources/validate/data-dir/advanced_regex_negative_lookbehind_non_compliant.yaml'),
    })

    expect(sanitizeSarifOutput(result)).toMatchSnapshot()
  })
  it('should handle a directory in data, a single rule file, and match the snapshot', async () => {
    const result = await validate({
      rulesPath: path.resolve(__dirname, '../../resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard'),
      dataPath: path.resolve(__dirname, '../../resources/validate/data-dir'),
    })

    expect(sanitizeSarifOutput(result)).toMatchSnapshot()
  })
  it('should handle a single data file, a single rule file, and match the snapshot', async () => {
    const result = await validate({
      rulesPath: path.resolve(__dirname, '../../resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard'),
      dataPath: path.resolve(__dirname, '../../resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml'),
    })

    expect(sanitizeSarifOutput(result)).toMatchSnapshot()
  })
  it('should handle nested directories in both and match the snapshot', async () => {
    const result = await validate({
      // These fixture files only contain rules or templates
      // within a subdirectory.
      rulesPath: path.resolve(__dirname, './__fixtures__/rules-dir'),
      dataPath: path.resolve(__dirname, './__fixtures__/data-dir'),
    })
    expect(result.runs[0].results.length).toBe(2)
    expect(sanitizeSarifOutput(result)).toMatchSnapshot()
  })
  it('should resolve with a document, not throw, for a rules file that does not parse', async () => {
    const result = await validate({
      rulesPath: path.resolve(__dirname, './__fixtures__/malformed-rules/missing-operand.guard'),
      dataPath: path.resolve(__dirname, './__fixtures__/data-dir'),
    })

    // Nothing was evaluated, so there is nothing to report as a result.
    expect(result.runs[0].results).toEqual([])
  })
  // The committed wasm predates the core's `invocations` member, so for a rules file that does not
  // parse it returns the same document as a clean run. This pins what the rebuilt wasm returns and
  // is skipped until that rebuild lands.
  it.skip('should report a failed invocation naming the rules file that does not parse', async () => {
    const rulesPath = path.resolve(__dirname, './__fixtures__/malformed-rules/missing-operand.guard')
    const result = await validate({
      rulesPath,
      dataPath: path.resolve(__dirname, './__fixtures__/data-dir'),
    })

    const [invocation] = result.runs[0].invocations ?? []
    expect(invocation.executionSuccessful).toBe(false)
    expect(invocation.toolConfigurationNotifications?.[0].message.text).toContain(
      `Rules file ${rulesPath} could not be parsed`
    )
  })
})
