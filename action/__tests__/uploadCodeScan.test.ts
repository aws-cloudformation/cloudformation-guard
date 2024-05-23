import { Buffer } from 'buffer'
import * as zlib from 'zlib'
import * as github from '@actions/github'
import * as getConfig from '../src/getConfig'
import { SarifReport } from 'cfn-guard'
import * as uploadCodeScan from '../src/uploadCodeScan'
import { jest, describe, it, expect } from '@jest/globals'
import { context } from '@actions/github'
import { mockSarifResult } from './__mocks/mockSarif'

jest.mock('@actions/github')
jest.mock('../src/getConfig')
jest.mock('@actions/core')
jest.mock('zlib')

describe('compressAndEncode', () => {
  it('should compress and encode the input string', async () => {
    const input = 'test input'
    const expectedBase64 = 'dGVzdCBpbnB1dA=='

    const mockGzip = {
      on: jest.fn((event, callback: (arg?: Buffer) => void) => {
        if (event === 'data') {
          callback(Buffer.from(input))
        } else if (event === 'end') {
          callback()
        }
      }),
      write: jest.fn(),
      end: jest.fn()
    }

    jest
      .spyOn(zlib, 'createGzip')
      .mockReturnValue(mockGzip as unknown as zlib.Gzip)

    const result = await uploadCodeScan.compressAndEncode(input)
    expect(result).toBe(expectedBase64)
  })
})

describe('uploadCodeScan', () => {
  it('should upload the SARIF report to the GitHub Code Scanning API', async () => {
    const mockConfig = {
      token: 'test-token'
    }

    jest
      .spyOn(getConfig, 'getConfig')
      .mockReturnValue(mockConfig as getConfig.Config)
    jest.spyOn(github, 'getOctokit').mockReturnValue({
      // @ts-ignore Just need to stop the spec to listen for a call and not execute.
      request: jest.fn().mockResolvedValue({})
    })
    jest
      .spyOn(uploadCodeScan, 'compressAndEncode')
      .mockResolvedValue('compressed-and-encoded-sarif')

    await uploadCodeScan.uploadCodeScan({ result: mockSarifResult })

    expect(getConfig.default).toHaveBeenCalled()
    expect(github.getOctokit).toHaveBeenCalledWith('test-token')
    expect(uploadCodeScan.compressAndEncode).toHaveBeenCalledWith(
      JSON.stringify(mockSarifResult)
    )
    expect(github.getOctokit('test-token').request).toHaveBeenCalledWith(
      'POST /repos/{owner}/{repo}/code-scanning/sarifs',
      {
        owner: 'owner',
        repo: 'repo',
        commit_sha: 'test-commit-id',
        ref: 'refs/heads/main',
        sarif: 'compressed-and-encoded-sarif',
        headers: {
          'X-GitHub-Api-Version': '2022-11-28'
        }
      }
    )
  })
})
