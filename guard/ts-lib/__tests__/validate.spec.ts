import { validate } from '../index.js'
import { sanitizeSarifOutput } from '../utils';
import * as path from 'path';
import { describe, expect, it } from '@jest/globals';

describe('validate', () => {
  const unsupportedFile = path.resolve(__dirname, '__fixtures__/unsupported_extension.txt')
  const supportedRulesFile = path.resolve(
    __dirname,
    '../../resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard'
  )
  const supportedDataFile = path.resolve(
    __dirname,
    '../../resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml'
  )

  it('should reject a named rules file whose extension is not supported', async () => {
    await expect(
      validate({
        rulesPath: unsupportedFile,
        dataPath: supportedDataFile,
      })
    ).rejects.toThrow('does not have a supported extension')
  })

  it('should reject a named data file whose extension is not supported', async () => {
    await expect(
      validate({
        rulesPath: supportedRulesFile,
        dataPath: unsupportedFile,
      })
    ).rejects.toThrow('does not have a supported extension')
  })

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
})
