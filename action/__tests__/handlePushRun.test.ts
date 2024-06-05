import { describe, it, expect } from '@jest/globals';
import { handlePushRun } from '../src/handlePushRun';
import { sarifRunFixture } from './__fixtures__/sarifFixtures';

describe('handlePushRun', () => {
  it('should return an array of violation details', async () => {
    const violations = await handlePushRun({ run: sarifRunFixture });

    expect(violations).toEqual([
      ['❌ file1.yaml:L10,C5', 'Violation message 1', 'rule1'],
      ['❌ file2.yaml:L15,C8', 'Violation message 2', 'rule2']
    ]);
  });
});
