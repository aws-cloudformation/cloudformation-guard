import * as core from '@actions/core';
import { ErrorStrings, GithubEventNames } from './stringEnums';
import {
  handleWriteActionSummary,
  handleWriteRulesFileFailureSummary
} from './handleWriteActionSummary';
import { checkoutRepository } from './checkoutRepository';
import { context } from '@actions/github';
import { debugLog } from './debugLog';
import getConfig from './getConfig';
import { handlePullRequestRun } from './handlePullRequestRun';
import { handlePushRun } from './handlePushRun';
import { handleValidate } from './handleValidate';
import { uploadCodeScan } from './uploadCodeScan';

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  debugLog('Running action');
  const { analyze, checkout } = getConfig();
  const { eventName } = context;
  debugLog(`Event type: ${eventName}`);
  if (checkout) {
    await checkoutRepository();
  }

  try {
    const result = await handleValidate();
    const {
      runs: [sarifRun]
    } = result;
    // An empty `results` array is a clean run only if every rules file was
    // evaluated. A rules file that did not parse shows up here, not as a
    // result, so the gate below would otherwise read it as a pass.
    const failedInvocations = (sarifRun.invocations ?? []).filter(
      invocation => !invocation.executionSuccessful
    );
    if (failedInvocations.length) {
      core.setFailed(ErrorStrings.RULES_FILE_FAILURE);
      const messages = failedInvocations.flatMap(invocation =>
        (invocation.toolConfigurationNotifications ?? []).map(
          notification => notification.message.text
        )
      );
      for (const message of messages) {
        core.setFailed(message);
      }
      try {
        await handleWriteRulesFileFailureSummary({ messages });
      } catch (error) {
        // The failures are already on the log through setFailed. A summary
        // that cannot be written (no step summary file on this runner) must
        // not stop the violations below from being reported.
        core.warning(`${ErrorStrings.SUMMARY_FAILURE}: ${error}`);
      }
    }
    if (sarifRun.results.length) {
      if (analyze) {
        debugLog('Using analyze');
        core.setFailed(
          `${ErrorStrings.VALIDATION_FAILURE} ${ErrorStrings.SECURITY_TAB}`
        );
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
