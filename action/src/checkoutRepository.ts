import { context } from '@actions/github';
import { exec } from '@actions/exec';

enum CheckoutRepositoryStrings {
  Error = 'Error checking out repository'
}

/**
 * Checkout the appropriate ref for the users changes.
 * @returns {Promise<void>}
 */
export async function checkoutRepository(): Promise<void> {
  const ref = context.payload.ref;
  const repository = context.payload.repository?.full_name;
  try {
    await exec('git init');
    await exec(`git remote add origin https://github.com/${repository}.git`);
    if (context.eventName === 'pull_request') {
      const prRef = `refs/pull/${context.payload.pull_request?.number}/merge`;
      await exec(`git fetch origin ${prRef}`);
      await exec(`git checkout -qf FETCH_HEAD`);
    } else {
      await exec(`git fetch origin ${ref}`);
      await exec(`git checkout FETCH_HEAD`);
    }
  } catch (error) {
    throw new Error(`${CheckoutRepositoryStrings.Error}: ${error}`);
  }
}

export default checkoutRepository;
