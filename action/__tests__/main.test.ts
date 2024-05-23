import * as mocks from './__mocks/mockSarif'
import * as core from '@actions/core'
import { run } from '../src/main'
import { describe, expect, it, jest, afterEach } from '@jest/globals'
import { checkoutRepository } from '../src/checkoutRepository'
import getConfig from '../src/getConfig'
import * as handleValidate from '../src/handleValidate'
import * as uploadCodeScan from '../src/uploadCodeScan'
import * as handlePullRequestRun from '../src/handlePullRequestRun'
import * as handlePushRun from '../src/handlePushRun'
import * as github from '@actions/github'
import { Context } from '@actions/github/lib/context'

jest.mock('../src/checkoutRepository', () => ({
  __esModule: true,
  checkoutRepository: jest.fn(),
  default: jest.fn()
}))
jest.mock('../src/handlePushRun', () => ({
  __esModule: true,
  handlePushRun: jest.fn().mockReturnValue([
    ['file1.ts', 'Violation message 1', 'rule-id-1'],
    ['file2.ts', 'Violation message 2', 'rule-id-2']
  ]),
  default: jest.fn()
}))
jest.mock('../src/handleValidate', () => {
  const mockResult = (jest.requireActual('./__mocks/mockSarif') as typeof mocks)
    .mockSarifResult
  return {
    __esModule: true,
    handleValidate: jest.fn().mockReturnValue(mockResult),
    default: jest.fn()
  }
})
jest.mock('../src/uploadCodeScan', () => ({
  __esModule: true,
  uploadCodeScan: jest.fn(),
  default: jest.fn()
}))
jest.mock('../src/handlePullRequestRun', () => {
  const { handlePullRequestRun: handlePullRequestRunActual } =
    jest.requireActual<typeof handlePullRequestRun>(
      '../src/handlePullRequestRun'
    )
  const handleCreateReviewSpy = jest.fn()
  return {
    __esModule: true,
    handlePullRequestRun: jest.fn(args => {
      handlePullRequestRunActual(
        args as handlePullRequestRun.HandlePullRequestRunParams
      )
      const config = jest.mocked(getConfig)()
      if (config.createReview) {
        handleCreateReviewSpy(args)
      }
      return [
        ['file1.ts', 'Violation message 1', 'rule-id-1'],
        ['file2.ts', 'Violation message 2', 'rule-id-2']
      ]
    }),
    handleCreateReview: handleCreateReviewSpy,
    default: jest.fn()
  }
})
jest.mock('../src/getConfig', () => {
  return {
    __esModule: true,
    default: jest.fn()
  }
})

describe('main', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  it('checks out, handles a pr, creates a review with a proper config', async () => {
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: false,
      checkout: true,
      createReview: true,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).not.toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).toHaveBeenCalled()
  })

  it('does not check out, handles a pr, creates a review with a proper config', async () => {
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: false,
      checkout: false,
      createReview: true,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).not.toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).not.toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).toHaveBeenCalled()
  })

  it('does not check out, handles a pr, does not create a review with a proper config', async () => {
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: false,
      checkout: false,
      createReview: false,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).not.toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).not.toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).not.toHaveBeenCalled()
  })

  it('checks out, handles a push with a proper config', async () => {
    github.context.eventName = 'push'
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: false,
      checkout: true,
      createReview: false,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).not.toHaveBeenCalled()
  })

  it('does not check out, handles a push with a proper config', async () => {
    github.context.eventName = 'push'
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: false,
      checkout: false,
      createReview: false,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).not.toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).not.toHaveBeenCalled()
  })

  it('checks out, analyzes code with a proper config', async () => {
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: true,
      checkout: true,
      createReview: true,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).not.toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).not.toHaveBeenCalled()
  })

  it('does not check out, analyzes code with a proper config', async () => {
    ;(getConfig as jest.Mock).mockReturnValue({
      analyze: true,
      checkout: false,
      createReview: true,
      dataPath: 'stub',
      rulesPath: 'stub',
      token: 'stub'
    })

    await run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Validation failure. CFN Guard found violations.'
    )
    expect(checkoutRepository).not.toHaveBeenCalled()
    expect(handleValidate.handleValidate).toHaveBeenCalled()
    expect(handlePushRun.handlePushRun).not.toHaveBeenCalled()
    expect(uploadCodeScan.uploadCodeScan).toHaveBeenCalled()
    expect(handlePullRequestRun.handlePullRequestRun).not.toHaveBeenCalled()
    expect(handlePullRequestRun.handleCreateReview).not.toHaveBeenCalled()
  })
})
