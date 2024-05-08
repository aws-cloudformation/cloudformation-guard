import { validate } from '../index.js'
import { sanitizeSarifOutput } from '../utils';
import * as path from 'path';

describe('validate', () => {
  it('should match the snapshot', async () => {
    const result = await validate({
      rulesPath: path.resolve(__dirname, '../../resources/validate/rules-dir'),
      dataPath: path.resolve(__dirname, '../../resources/validate/data-dir'),
    })

    expect(sanitizeSarifOutput(result)).toMatchSnapshot()
  })
})
