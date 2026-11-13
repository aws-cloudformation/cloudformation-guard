import { SarifRegion } from 'cfn-guard';
import getConfig from './getConfig';

/**
 * Render a SARIF region as `L<line>,C<column>`, with `?` for a line or a
 * column the core did not report. A result with no region is a finding whose
 * position is unknown; the core says so by omitting the region rather than by
 * reporting line 1.
 *
 * @function formatPosition
 * @param {SarifRegion | undefined} region - The result's region, if it has one
 * @returns {string}
 */
export function formatPosition(region?: SarifRegion): string {
  return `L${region?.startLine ?? '?'},C${region?.startColumn ?? '?'}`;
}

/**
 * Handle adding the root when a user supplies a path
 *
 * @function addRootPath
 * @param {string} path - A file path
 * @returns {string}
 */
export function addRootPath(path: string): string {
  const { path: root } = getConfig();
  if (path.startsWith('./')) {
    return `${root}${path.slice(1)}`;
  } else if (!path.startsWith(root)) {
    return `${root}/${path}`;
  }
  return path;
}

/**
 * Handle removing the root when a user supplies a path
 *
 * @function removeRootPath
 * @param {string} uri - File location URI
 * @returns {string}
 */
export function removeRootPath(uri: string): string {
  const { path } = getConfig();
  if (uri.startsWith(path)) {
    const pathWithoutRoot = uri.slice(path.length);
    return pathWithoutRoot.startsWith('/')
      ? pathWithoutRoot.slice(1)
      : pathWithoutRoot;
  }
  return uri;
}
