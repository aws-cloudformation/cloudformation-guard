import * as core from '@actions/core';
import { SummaryStrings } from './stringEnums';
import debugLog from './debugLog';

type HandleWriteActionSummaryParams = {
  results: string[][];
};

type HandleWriteRulesFileFailureSummaryParams = {
  messages: string[];
};

/**
 * Writes the rules files that could not be evaluated to the GitHub Actions summary, so a run that
 * failed for that reason says why there as well as in the log.
 * @param {HandleWriteRulesFileFailureSummaryParams} params - The parameters for writing the summary.
 * @param {string[]} params.messages - One message per rules file, as reported by cfn-guard.
 * @returns {Promise<void>} - Resolves when the action summary has been written.
 */
export async function handleWriteRulesFileFailureSummary({
  messages
}: HandleWriteRulesFileFailureSummaryParams): Promise<void> {
  debugLog('Writing rules file failure summary...');

  await core.summary
    .addHeading(SummaryStrings.RULES_FILE_HEADING)
    .addList(messages)
    .write();
}

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
