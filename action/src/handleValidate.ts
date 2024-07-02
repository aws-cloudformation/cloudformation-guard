import * as core from '@actions/core';
import { SarifReport, validate } from 'cfn-guard';
import { addRootPath } from './utils';
import debugLog from './debugLog';
import getConfig from './getConfig';

/**
 * Handles the validation of the CloudFormation templates using CFN Guard.
 * @returns {Promise<SarifReport>} - The SARIF report containing the validation results.
 */
export async function handleValidate(): Promise<SarifReport> {
  const { rulesPath, dataPath, path } = getConfig();
  debugLog(`Rules path sent to validation: ${rulesPath}`);
  debugLog(`Data path sent to validation: ${dataPath}`);

  const result = await validate({
    dataPath: path.length ? addRootPath(dataPath) : dataPath,
    rulesPath: path.length ? addRootPath(rulesPath) : rulesPath
  });

  debugLog(`Validation result: ${JSON.stringify(result, null, 2)}`);

  core.setOutput('result', JSON.stringify(result, null, 2));

  return result;
}
