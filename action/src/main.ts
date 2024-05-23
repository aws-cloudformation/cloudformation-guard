import * as core from '@actions/core';
import { checkoutRepository } from './checkoutRepository';
import { context } from '@actions/github';
import getConfig from './getConfig';
import { handlePullRequestRun } from './handlePullRequestRun';
import { handlePushRun } from './handlePushRun';
import { handleValidate } from './handleValidate';
import { handleWriteActionSummary } from './handleWriteActionSummary';
import { uploadCodeScan } from './uploadCodeScan';

export enum RunStrings {
  ValidationFailed = 'Validation failure. cfn-guard found violations.',
  Error = 'Action failed with error'
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  const { analyze, checkout } = getConfig();
  const { eventName } = context;

  checkout && (await checkoutRepository());

  try {
    const result = await handleValidate();
    const {
      runs: [sarifRun]
    } = result;

    if (sarifRun.results.length) {
      if (analyze) {
        core.setFailed(RunStrings.ValidationFailed);
        await uploadCodeScan({ result });
      } else {
        const results =
          eventName === 'pull_request'
            ? await handlePullRequestRun({ run: sarifRun })
            : await handlePushRun({ run: sarifRun });
        if (results.length) {
          core.setFailed(RunStrings.ValidationFailed);
          await handleWriteActionSummary({
            results
          });
        }
      }
    }
  } catch (error) {
    core.setFailed(`${RunStrings.Error}: ${error}`);
  }
}
