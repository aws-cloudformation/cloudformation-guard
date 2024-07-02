import { blobToBase64 } from './blobToBase64';
import debugLog from './debugLog';
import zlib from 'zlib';
/**
 * Compresses and encodes the input string using gzip and base64.
 * @param {string} input - The input string to be compressed and encoded.
 * @returns {Promise<string>} - The compressed and base64-encoded string.
 */
export async function compressAndEncode(input: string): Promise<string> {
  debugLog('Compressing results...');

  const byteArray = Buffer.from(input, 'utf8');
  const gzip = zlib.createGzip();

  const compressedData = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];

    gzip.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    gzip.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    gzip.on('error', (error: Error) => {
      reject(error);
    });

    gzip.write(byteArray);
    gzip.end();
  });

  const base64 = await blobToBase64(compressedData);
  return base64;
}
