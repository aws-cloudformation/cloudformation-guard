import { Buffer } from 'buffer';
import zlib from 'zlib';
import { context, getOctokit } from '@actions/github';
import getConfig from './getConfig';
import { SarifReport } from 'cfn-guard';
import { Readable } from 'stream';

enum Endpoints {
  CodeScan = 'POST /repos/{owner}/{repo}/code-scanning/sarifs'
}

/**
 * Compresses and encodes the input string using gzip and base64.
 * @param {string} input - The input string to be compressed and encoded.
 * @returns {Promise<string>} - The compressed and base64-encoded string.
 */
export const compressAndEncode = async (input: string): Promise<string> => {
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
};

/**
 * Converts a Buffer to a base64-encoded string.
 * @param {Buffer} blob - The Buffer to be converted to base64.
 * @returns {Promise<string>} - The base64-encoded string.
 */
const blobToBase64 = async (blob: Buffer): Promise<string> => {
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
};

export type UploadCodeScanParams = {
  result: SarifReport;
};

/**
 * Uploads the SARIF report to the GitHub Code Scanning API.
 * @param {UploadCodeScanParams} params - The parameters for the code scan upload.
 * @returns {Promise<void>} - Resolves when the code scan has been uploaded successfully.
 */
export const uploadCodeScan = async ({
  result
}: UploadCodeScanParams): Promise<void> => {
  const { token } = getConfig();
  const ref = context.payload.ref;
  const octokit = getOctokit(token);
  const headers = { 'X-GitHub-Api-Version': '2022-11-28' };

  const params = {
    ...context.repo,
    commit_sha: context.payload.head_commit.id,
    ref,
    // SARIF reports must be gzipped and base64 encoded for the code scanning API
    // https://docs.github.com/en/rest/code-scanning/code-scanning?apiVersion=2022-11-28#upload-an-analysis-as-sarif-data
    sarif: await compressAndEncode(JSON.stringify(result)),
    headers
  };

  await octokit.request(Endpoints.CodeScan, params);
};
