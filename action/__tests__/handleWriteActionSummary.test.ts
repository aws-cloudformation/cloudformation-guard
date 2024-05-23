import * as core from '@actions/core';
import { handleWriteActionSummary } from '../src/handleWriteActionSummary';
import { jest, describe, it, expect } from '@jest/globals';

jest.mock('@actions/core', () => {
  return {
    summary: {
      addHeading: jest.fn().mockReturnValue({
        addTable: jest.fn().mockReturnValue({
          write: jest.fn()
        })
      })
    }
  };
});

describe('handleWriteActionSummary', () => {
  it('should write the validation results to the GitHub Actions summary', async () => {
    const mockResults = [
      ['file1.ts', 'Violation message 1', 'rule-id-1'],
      ['file2.ts', 'Violation message 2', 'rule-id-2']
    ];

    await handleWriteActionSummary({ results: mockResults });

    expect(core.summary.addHeading).toHaveBeenCalledWith('Validation Failures');
    expect(core.summary.addHeading('').addTable).toHaveBeenCalledWith([
      [
        { data: 'File', header: true },
        { data: 'Reason', header: true },
        { data: 'Rule', header: true }
      ],
      ...mockResults
    ]);
    expect(core.summary.addHeading('').addTable([]).write).toHaveBeenCalled();
  });
});
