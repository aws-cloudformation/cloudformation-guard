import * as github from '@actions/github';
import * as getConfig from '../src/getConfig';
import * as uploadCodeScan from '../src/uploadCodeScan';
import { jest, describe, it, expect, beforeAll } from '@jest/globals';
import { sarifResultFixture } from './__fixtures__/sarifFixtures';
import * as compressAndEncode from '../src/compressAndEncode';

jest.mock('@actions/github');
jest.mock('../src/getConfig');
jest.mock('@actions/core');

describe('uploadCodeScan', () => {
  it('should upload the SARIF report to the GitHub Code Scanning API', async () => {
    const mockConfig = {
      token: 'test-token'
    };

    jest
      .spyOn(getConfig, 'getConfig')
      .mockReturnValue(mockConfig as getConfig.Config);
    jest.spyOn(github, 'getOctokit').mockReturnValue({
      // @ts-ignore Just need to stop the spec to listen for a call and not execute.
      request: jest.fn().mockResolvedValue({})
    });
    jest
      .spyOn(compressAndEncode, 'compressAndEncode')
      .mockResolvedValue('compressed-and-encoded-sarif');

    await uploadCodeScan.uploadCodeScan({ result: sarifResultFixture });

    expect(getConfig.default).toHaveBeenCalled();
    expect(github.getOctokit).toHaveBeenCalledWith('test-token');
    expect(compressAndEncode.compressAndEncode).toHaveBeenCalledWith(
      JSON.stringify(sarifResultFixture)
    );
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
    );
  });
});
