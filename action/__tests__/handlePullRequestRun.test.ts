import { handlePullRequestRun } from '../src/handlePullRequestRun';
import { describe, expect, it } from '@jest/globals';
import { sarifRunFixture } from './__fixtures__/sarifFixtures';
import { context } from '@actions/github';

describe('handlePullRequestRun success', () => {
  it('should handle the pull request run successfully', async () => {
    const result = await handlePullRequestRun({ run: sarifRunFixture });

    expect(result).toEqual([
      ['❌ file1.yaml:L10,C5', 'Violation message 1', 'rule1'],
      ['❌ file2.yaml:L15,C8', 'Violation message 2', 'rule2']
    ]);
  });
});

describe('handlePullRequestRun failure', () => {
  it('should throw an error if the pull request context is not found', async () => {
    // @ts-ignore pull request should be empty for this case
    context.payload.pull_request = null;
    await expect(
      handlePullRequestRun({ run: sarifRunFixture })
    ).rejects.toThrow(
      'Tried to handle pull request result but could not find PR context.'
    );
  });
});
