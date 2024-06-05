import * as core from '@actions/core';
import { SarifReport, validate } from 'cfn-guard';
import getConfig from './getConfig';

/**
 * Handles the validation of the CloudFormation templates using CFN Guard.
 * @returns {Promise<SarifReport>} - The SARIF report containing the validation results.
 */
export async function handleValidate(): Promise<SarifReport> {
  const { rulesPath, dataPath } = getConfig();

  const result = await validate({
    dataPath,
    rulesPath
  });

  core.setOutput('result', JSON.stringify(result, null, 2));

  return result;
}
