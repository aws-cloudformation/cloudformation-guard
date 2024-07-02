import { context, getOctokit } from '@actions/github';
import { ErrorStrings } from './stringEnums';
import { SarifRun } from 'cfn-guard';
import debugLog from './debugLog';
import getConfig from './getConfig';
import { removeRootPath } from './utils';

export type HandlePullRequestRunParams = {
  run: SarifRun;
};

type Comments = {
  body: string;
  path: string;
  position: number;
}[];

type HandleCreateReviewParams = {
  tmpComments: Comments;
  filesWithViolationsInPr: string[];
};

/**
 * Handle the creation of a review on a pull request.
 *
 * @async
 * @function handleCreateReview
 * @param {HandleCreateReviewParams} params - The parameters for creating the review.
 * @param {Comments} params.tmpComments - The temporary comments to be filtered and added to the review.
 * @param {string[]} params.filesWithViolationsInPr - The list of files with violations in the pull request.
 * @returns {Promise<void>}
 */
export async function handleCreateReview({
  tmpComments,
  filesWithViolationsInPr
}: HandleCreateReviewParams): Promise<void> {
  const { token } = getConfig();
  const { pull_request } = context.payload;
  if (!pull_request) return;
  const octokit = getOctokit(token);

  const comments = tmpComments.filter(comment =>
    filesWithViolationsInPr.includes(comment.path)
  );

  debugLog(
    `Creating a review with comments: ${JSON.stringify(comments, null, 2)}`
  );

  for (const comment of comments) {
    try {
      await octokit.rest.pulls.createReview({
        ...context.repo,
        comments: [comment],
        commit_id: pull_request.head.sha,
        event: 'COMMENT',
        pull_number: pull_request.number
      });
    } catch (error) {
      // This logs out if the comment couldn't post
      // because the line position isn't a part of the diff.
      // This should not be a problem because we can only
      // review what we can see.
      console.error(error);
    }
  }
}

/**
 * Handles formatting the reported execution of a pull request run for the CFN Guard action.
 * @param {HandlePullRequestRunParams} params - The parameters for the pull request run.
 * @param {SarifRun} params.run - The SARIF run object containing the validation results.
 * @returns {Promise<string[][]>} - An array of arrays, where each inner array represents a violation with the following format: [file path, violation message, rule ID].
 * @throws {Error} - Throws an error if the pull request context cannot be found.
 */
export async function handlePullRequestRun({
  run
}: HandlePullRequestRunParams): Promise<string[][]> {
  debugLog('Handling PR run...');

  const MAX_PER_PAGE = 3000;
  const { token, createReview, path: root } = getConfig();
  const octokit = getOctokit(token);
  const { pull_request } = context.payload;

  if (!pull_request) {
    throw new Error(ErrorStrings.PULL_REQUEST_ERROR);
  }

  const listFiles = await octokit.rest.pulls.listFiles({
    ...context.repo,
    per_page: MAX_PER_PAGE,
    pull_number: pull_request.number
  });

  const filesChanged = listFiles.data.map(({ filename }) => filename);

  debugLog(`Files changed: ${JSON.stringify(filesChanged, null, 2)}`);

  const tmpComments = run.results.map(result => {
    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    const path = root?.length ? removeRootPath(uri) : uri;
    return {
      body: result.message.text,
      path,
      position: result.locations[0].physicalLocation.region.startLine
    };
  });

  const filesWithViolations = tmpComments.map(({ path }) => path);

  debugLog(
    `Files with violations: ${JSON.stringify(filesWithViolations, null, 2)}`
  );

  const filesWithViolationsInPr = filesChanged.filter(value =>
    filesWithViolations.includes(value)
  );

  debugLog(
    `Files with violations in PR: ${JSON.stringify(filesWithViolationsInPr, null, 2)}`
  );

  filesWithViolationsInPr.length &&
    createReview &&
    (await handleCreateReview({
      filesWithViolationsInPr,
      tmpComments
    }));

  return run.results
    .map(({ locations: [location], ruleId, message: { text } }) => {
      const uri = location.physicalLocation.artifactLocation.uri;
      return filesWithViolationsInPr.includes(
        root?.length ? removeRootPath(uri) : uri
      )
        ? [
            `❌ ${uri}:L${location.physicalLocation.region.startLine},C${location.physicalLocation.region.startColumn}`,
            text,
            ruleId
          ]
        : [];
    })
    .filter(result => result.some(Boolean));
}
