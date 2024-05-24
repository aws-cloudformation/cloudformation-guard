import * as core from '@actions/core';
import { ErrorStrings, GithubEventNames } from './stringEnums';
import { checkoutRepository } from './checkoutRepository';
import { context } from '@actions/github';
import getConfig from './getConfig';
import { handlePullRequestRun } from './handlePullRequestRun';
import { handlePushRun } from './handlePushRun';
import { handleValidate } from './handleValidate';
import { handleWriteActionSummary } from './handleWriteActionSummary';
import { uploadCodeScan } from './uploadCodeScan';

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
        core.setFailed(ErrorStrings.VALIDATION_FAILURE);
        await uploadCodeScan({ result });
      } else {
        const results =
          eventName === GithubEventNames.PULL_REQUEST
            ? await handlePullRequestRun({ run: sarifRun })
            : await handlePushRun({ run: sarifRun });
        if (results.length) {
          core.setFailed(ErrorStrings.VALIDATION_FAILURE);
          await handleWriteActionSummary({
            results
          });
        }
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`${ErrorStrings.ACTION_FAILURE}: ${error}`);
    } else {
      core.setFailed(
        `${ErrorStrings.ACTION_FAILURE}: ${JSON.stringify(error)}`
      );
    }
  }
}
