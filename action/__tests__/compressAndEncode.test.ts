import { Buffer } from 'buffer';
import { jest, describe, it, expect } from '@jest/globals';
import * as zlib from 'zlib';
import { compressAndEncode } from '../src/compressAndEncode';

jest.mock('zlib');

describe('compressAndEncode', () => {
  it('should compress and encode the input string', async () => {
    const input = 'test input';
    const expectedBase64 = 'dGVzdCBpbnB1dA==';

    const mockGzip = {
      on: jest.fn((event, callback: (arg?: Buffer) => void) => {
        if (event === 'data') {
          callback(Buffer.from(input));
        } else if (event === 'end') {
          callback();
        }
      }),
      write: jest.fn(),
      end: jest.fn()
    };

    jest
      .spyOn(zlib, 'createGzip')
      .mockReturnValue(mockGzip as unknown as zlib.Gzip);

    const result = await compressAndEncode(input);
    expect(result).toBe(expectedBase64);
  });
});
