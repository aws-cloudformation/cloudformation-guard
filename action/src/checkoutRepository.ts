import { context, getOctokit } from '@actions/github';
import { ErrorStrings } from './stringEnums';
import { checkoutPrivateRepository } from './checkoutPrivateRepository';
import { checkoutPublicRepository } from './checkoutPublicRepository';
import debugLog from './debugLog';
import getConfig from './getConfig';

/**
 * Check if the repository is private and call the appropriate checkout function.
 * @returns {Promise<void>}
 */
export async function checkoutRepository(): Promise<void> {
  debugLog('Checking out repo');
  const { token } = getConfig();
  const repository = context.payload.repository?.full_name;

  if (!repository) {
    throw new Error(ErrorStrings.CHECKOUT_REPOSITORY_ERROR);
  }

  const octokit = getOctokit(token);

  try {
    const { data: repoData } = await octokit.rest.repos.get({
      owner: context.repo.owner,
      repo: context.repo.repo
    });

    const isPrivate = repoData.private;

    if (isPrivate) {
      await checkoutPrivateRepository();
    } else {
      await checkoutPublicRepository();
    }
  } catch (error) {
    throw new Error(`${ErrorStrings.CHECKOUT_REPOSITORY_ERROR}: ${error}`);
  }
}

export default checkoutRepository;
