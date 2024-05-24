/**
 * Unit tests for the action's entrypoint, src/index.ts
 */

import * as main from '../src/main';
import { describe, expect, jest, it } from '@jest/globals';

// Mock the action's entrypoint
const runMock = jest
  .spyOn(main, 'run')
  .mockImplementation(() => Promise.resolve());

describe('index', () => {
  it('calls run when imported', async () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('../src/index');

    expect(runMock).toHaveBeenCalled();
  });
});
