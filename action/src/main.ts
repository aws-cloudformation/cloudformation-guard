import * as core from '@actions/core'
import { context } from '@actions/github'
import { checkoutRepository } from './checkoutRepository'
import { uploadCodeScan } from './uploadCodeScan'
import { handleValidate } from './handleValidate'
import { handlePullRequestRun } from './handlePullRequestRun'
import { handlePushRun } from './handlePushRun'
import { handleWriteActionSummary } from './handleWriteActionSummary'
import getConfig from './getConfig'

enum RunStrings {
  ValidationFailed = 'Validation failure. CFN Guard found violations.',
  Error = 'Action failed with error'
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  const { analyze, checkout } = getConfig()
  const { eventName } = context

  checkout && (await checkoutRepository())

  try {
    const result = await handleValidate()
    const {
      runs: [run]
    } = result

    if (run.results.length) {
      core.setFailed(RunStrings.ValidationFailed)

      if (analyze) {
        await uploadCodeScan({ result })
      } else {
        await handleWriteActionSummary({
          results:
            eventName === 'pull_request'
              ? await handlePullRequestRun({ run })
              : await handlePushRun({ run })
        })
      }
    }
  } catch (error) {
    core.setFailed(`${RunStrings.Error}: ${error}`)
  }
}
