import { context, getOctokit } from '@actions/github';
import { ErrorStrings } from './stringEnums';
import { SarifRun } from 'cfn-guard';
import getConfig from './getConfig';

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

  await octokit.rest.pulls.createReview({
    ...context.repo,
    comments,
    commit_id: context.payload.head_commit,
    event: 'COMMENT',
    pull_number: pull_request.number
  });
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
  const MAX_PER_PAGE = 3000;
  const { token, createReview } = getConfig();
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

  const tmpComments = run.results.map(result => ({
    body: result.message.text,
    path: result.locations[0].physicalLocation.artifactLocation.uri,
    position: result.locations[0].physicalLocation.region.startLine
  }));

  const filesWithViolations = tmpComments.map(({ path }) => path);

  const filesWithViolationsInPr = filesChanged.filter(value =>
    filesWithViolations.includes(value)
  );

  filesWithViolationsInPr.length &&
    createReview &&
    (await handleCreateReview({
      filesWithViolationsInPr,
      tmpComments
    }));

  return run.results
    .map(({ locations: [location], ruleId, message: { text } }) =>
      filesWithViolationsInPr.includes(
        location.physicalLocation.artifactLocation.uri
      )
        ? [
            `❌ ${location.physicalLocation.artifactLocation.uri}:L${location.physicalLocation.region.startLine},C${location.physicalLocation.region.startColumn}`,
            text,
            ruleId
          ]
        : []
    )
    .filter(result => result.some(Boolean));
}
