import * as core from '@actions/core';
import { SummaryStrings } from './stringEnums';
import debugLog from './debugLog';

type HandleWriteActionSummaryParams = {
  results: string[][];
};

/**
 * Writes a summary of the validation results to the GitHub Actions summary.
 * @param {HandleWriteActionSummaryParams} params - The parameters for writing the action summary.
 * @param {string[][]} params.results - A 2D array of strings representing the validation results. Each inner array contains the file path, violation message, and rule ID.
 * @returns {Promise<void>} - Resolves when the action summary has been written.
 */
export async function handleWriteActionSummary({
  results
}: HandleWriteActionSummaryParams): Promise<void> {
  debugLog('Writing summary...');

  await core.summary
    .addHeading(SummaryStrings.HEADING)
    .addTable([
      [
        { data: SummaryStrings.FILE, header: true },
        { data: SummaryStrings.REASON, header: true },
        { data: SummaryStrings.RULE, header: true }
      ],
      ...results
    ])
    .write();
}
