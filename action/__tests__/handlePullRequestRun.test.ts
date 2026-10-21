import { handlePullRequestRun } from '../src/handlePullRequestRun';
import { describe, expect, it, jest } from '@jest/globals';
import {
  sarifRunFixture,
  sarifRunFixtureWithoutRegion
} from './__fixtures__/sarifFixtures';
import { context, getOctokit } from '@actions/github';

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

describe('handlePullRequestRun without a region', () => {
  it('should report the finding and leave the inline comment to findings with a line', async () => {
    context.payload.pull_request = { number: 123, head: { sha: 'sha' } };
    const createReview = jest.mocked(getOctokit)('token').rest.pulls
      .createReview as jest.Mock;
    createReview.mockClear();

    const result = await handlePullRequestRun({
      run: sarifRunFixtureWithoutRegion
    });

    expect(result).toEqual([
      ['❌ file1.yaml:L?,C?', 'Violation message 1', 'rule1'],
      ['❌ file2.yaml:L15,C?', 'Violation message 2', 'rule2']
    ]);
    // A review comment is anchored to a line, so only the finding that has one
    // gets a comment.
    expect(createReview).toHaveBeenCalledTimes(1);
    expect(createReview).toHaveBeenCalledWith(
      expect.objectContaining({
        comments: [
          { body: 'Violation message 2', path: 'file2.yaml', position: 15 }
        ]
      })
    );
  });
});
