import getConfig from './getConfig';
import * as core from '@actions/core';
import { SarifReport, validate } from 'cfn-guard';

/**
 * Handles the validation of the CloudFormation templates using CFN Guard.
 * @returns {Promise<SarifReport>} - The SARIF report containing the validation results.
 */
export const handleValidate = async (): Promise<SarifReport> => {
  const { rulesPath, dataPath } = getConfig();

  const result = await validate({
    rulesPath,
    dataPath
  });

  core.setOutput('result', JSON.stringify(result, null, 2));

  return result;
};
