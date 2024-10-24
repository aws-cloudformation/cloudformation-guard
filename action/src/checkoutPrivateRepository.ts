import { ErrorStrings, GithubEventNames } from './stringEnums';
import { context } from '@actions/github';
import debugLog from './debugLog';
import { exec } from '@actions/exec';

/**
 * Checkout the appropriate ref for the users changes using gh cli.
 * @returns {Promise<void>}
 */
export async function checkoutPrivateRepository(): Promise<void> {
  debugLog('Checking out private repo');
  const sha = context.sha;
  const repository = context.payload.repository?.full_name;

  try {
    await exec(`gh repo clone ${repository} .`);
    if (context.eventName === GithubEventNames.PULL_REQUEST) {
      const prNumber = context.payload.pull_request?.number;
      debugLog(`Checking out PR ${prNumber}`);
      await exec(`gh pr checkout ${prNumber}`);
    } else {
      debugLog(`Checking out SHA ${sha}`);
      await exec('gh repo sync');
      await exec(`git checkout ${sha}`);
    }
  } catch (error) {
    throw new Error(`${ErrorStrings.CHECKOUT_REPOSITORY_ERROR}: ${error}`);
  }
}
