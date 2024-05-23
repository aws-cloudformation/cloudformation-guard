import { SarifRun } from 'cfn-guard';

type HandlePushRunParams = {
  run: SarifRun;
};

/**
 * Handles the execution of a push run for the CFN Guard action.
 * @param {HandlePushRunParams} params - The parameters for the push run.
 * @param {SarifRun} params.run - The SARIF run object containing the validation results.
 * @returns {Promise<string[][]>} - An array of arrays, where each inner array represents a violation with the following format: [file path, violation message, rule ID].
 */
export async function handlePushRun({
  run
}: HandlePushRunParams): Promise<string[][]> {
  return run.results.map(
    ({ locations: [location], ruleId, message: { text } }) => [
      `❌ ${location.physicalLocation.artifactLocation.uri}:L${location.physicalLocation.region.startLine},C${location.physicalLocation.region.startColumn}`,
      text,
      ruleId
    ]
  );
}
