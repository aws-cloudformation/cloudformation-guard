export enum GithubEventNames {
  PULL_REQUEST = 'pull_request',
  PUSH = 'push'
}

export enum ErrorStrings {
  ACTION_FAILURE = 'Action failed with error',
  CHECKOUT_REPOSITORY_ERROR = 'Error checking out repository',
  PULL_REQUEST_ERROR = 'Tried to handle pull request result but could not find PR context.',
  VALIDATION_FAILURE = 'Validation failure. cfn-guard found violations.',
  SECURITY_TAB = 'Check the security tab for results.'
}

export enum SummaryStrings {
  FILE = 'File',
  HEADING = 'Validation Failures',
  REASON = 'Reason',
  RULE = 'Rule'
}
