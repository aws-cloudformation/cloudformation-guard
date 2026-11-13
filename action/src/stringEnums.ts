export enum GithubEventNames {
  PULL_REQUEST = 'pull_request',
  PUSH = 'push'
}

export enum ErrorStrings {
  ACTION_FAILURE = 'Action failed with error',
  CHECKOUT_REPOSITORY_ERROR = 'Error checking out repository',
  PULL_REQUEST_ERROR = 'Tried to handle pull request result but could not find PR context.',
  VALIDATION_FAILURE = 'Validation failure. cfn-guard found violations.',
  SECURITY_TAB = 'Check the security tab for results.',
  PATH_ERROR = 'Could not navigate to supplied path. Either path is wrong or the runner is using an unsupported operating system.',
  RULES_FILE_FAILURE = 'Validation failure. cfn-guard could not evaluate every rules file.',
  SUMMARY_FAILURE = 'Could not write the rules file failure summary'
}

export enum SummaryStrings {
  FILE = 'File',
  HEADING = 'Validation Failures',
  REASON = 'Reason',
  RULE = 'Rule',
  RULES_FILE_HEADING = 'Rules Files Not Evaluated'
}
