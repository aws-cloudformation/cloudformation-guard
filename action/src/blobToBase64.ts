import { Buffer } from 'buffer';
import { Readable } from 'stream';
import debugLog from './debugLog';
/**
 * Converts a Buffer to a base64-encoded string.
 * @param {Buffer} blob - The Buffer to be converted to base64.
 * @returns {Promise<string>} - The base64-encoded string.
 */
export async function blobToBase64(blob: Buffer): Promise<string> {
  debugLog('Encoding results...');

  const reader = new Readable();
  reader._read = () => {}; // _read is required but you can noop it
  reader.push(blob);
  reader.push(null);

  return new Promise<string>((resolve, reject) => {
    reader.on('data', (chunk: Buffer) => {
      const base64 = chunk.toString('base64');
      resolve(base64);
    });

    reader.on('error', (error: Error) => {
      reject(error);
    });
  });
}
