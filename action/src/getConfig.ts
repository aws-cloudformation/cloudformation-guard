import * as core from '@actions/core';

export type Config = {
  rulesPath: string;
  dataPath: string;
  token: string;
  analyze: boolean;
  checkout: boolean;
  createReview: boolean;
};

/**
 * Returns the config values in JSON format
 * @returns {Config}
 */
export const getConfig = (): Config => ({
  rulesPath: core.getInput('rules'),
  dataPath: core.getInput('data'),
  token: core.getInput('token'),
  checkout: core.getBooleanInput('checkout'),
  analyze: core.getBooleanInput('analyze'),
  createReview: core.getBooleanInput('create-review')
});

export default getConfig;
