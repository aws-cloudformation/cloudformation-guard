import * as core from '@actions/core'

type HandleWriteActionSummaryParams = {
  results: string[][]
}

enum ValidationSummaryStrings {
  File = 'File',
  Reason = 'Reason',
  Rule = 'Rule',
  Heading = 'Validation Failures'
}

/**
 * Writes a summary of the validation results to the GitHub Actions summary.
 * @param {HandleWriteActionSummaryParams} params - The parameters for writing the action summary.
 * @param {string[][]} params.results - A 2D array of strings representing the validation results. Each inner array contains the file path, violation message, and rule ID.
 * @returns {Promise<void>} - Resolves when the action summary has been written.
 */
export const handleWriteActionSummary = async ({
  results
}: HandleWriteActionSummaryParams): Promise<void> => {
  await core.summary
    .addHeading(ValidationSummaryStrings.Heading)
    .addTable([
      [
        { data: ValidationSummaryStrings.File, header: true },
        { data: ValidationSummaryStrings.Reason, header: true },
        { data: ValidationSummaryStrings.Rule, header: true }
      ],
      ...results
    ])
    .write()
}
