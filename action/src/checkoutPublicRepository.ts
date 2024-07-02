import { ErrorStrings, GithubEventNames } from './stringEnums';
import { context } from '@actions/github';
import { debugLog } from './debugLog';
import { exec } from '@actions/exec';
/**
 * Checkout the appropriate ref for the users changes using git.
 * @returns {Promise<void>}
 */
export async function checkoutPublicRepository(): Promise<void> {
  debugLog('Checking out public repo');
  const ref = context.payload.ref ?? context.ref;
  const repository = context.payload.repository?.full_name;
  try {
    await exec('git init');
    await exec(`git remote add origin https://github.com/${repository}.git`);
    if (context.eventName === GithubEventNames.PULL_REQUEST) {
      const prRef = `refs/pull/${context.payload.pull_request?.number}/merge`;
      debugLog(`Checking out PR ref ${prRef}`);
      await exec(`git fetch origin ${prRef}`);
      await exec(`git checkout -qf FETCH_HEAD`);
    } else {
      debugLog(`Checking out ref ${ref}`);
      await exec(`git fetch origin ${ref}`);
      await exec(`git checkout FETCH_HEAD`);
    }
  } catch (error) {
    throw new Error(`${ErrorStrings.CHECKOUT_REPOSITORY_ERROR}: ${error}`);
  }
}
