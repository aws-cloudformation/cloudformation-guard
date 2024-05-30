import { ErrorStrings, GithubEventNames } from './stringEnums';
import { context } from '@actions/github';
import { exec } from '@actions/exec';

/**
 * Checkout the appropriate ref for the users changes using git.
 * @returns {Promise<void>}
 */
export async function checkoutPublicRepository(): Promise<void> {
  const ref = context.payload.ref;
  const repository = context.payload.repository?.full_name;
  try {
    await exec('git init');
    await exec(`git remote add origin https://github.com/${repository}.git`);
    if (context.eventName === GithubEventNames.PULL_REQUEST) {
      const prRef = `refs/pull/${context.payload.pull_request?.number}/merge`;
      await exec(`git fetch origin ${prRef}`);
      await exec(`git checkout -qf FETCH_HEAD`);
    } else {
      await exec(`git fetch origin ${ref}`);
      await exec(`git checkout FETCH_HEAD`);
    }
  } catch (error) {
    throw new Error(`${ErrorStrings.CHECKOUT_REPOSITORY_ERROR}: ${error}`);
  }
}
