import * as core from '@actions/core'
import getConfig, { Config } from '../src/getConfig'
import { describe, expect, it } from '@jest/globals'

describe('getConfig', () => {
  it('should return the correct config values', () => {
    const config: Config = getConfig()

    expect(core.getInput).toHaveBeenCalledWith('rules')
    expect(core.getInput).toHaveBeenCalledWith('data')
    expect(core.getInput).toHaveBeenCalledWith('token')
    expect(core.getBooleanInput).toHaveBeenCalledWith('checkout')
    expect(core.getBooleanInput).toHaveBeenCalledWith('analyze')
    expect(core.getBooleanInput).toHaveBeenCalledWith('create-review')

    expect(config).toEqual({
      rulesPath: 'test-rules-path',
      dataPath: 'test-data-path',
      token: 'test-token',
      checkout: true,
      analyze: true,
      createReview: true
    })
  })
})
