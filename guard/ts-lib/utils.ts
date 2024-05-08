import { SarifReport, SarifArtifact, SarifResult, SarifLocation, SarifDriver } from './index';
import { orderBy } from 'lodash';

function sanitizeProperty<T extends Record<string, any>>(obj: T, key: keyof T, newValue: string): T {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  for (const prop in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, prop)) {
      const value = obj[prop];

      if (prop === key && typeof value === 'string') {
        (obj as any)[prop] = newValue;
      } else if (typeof value === 'object' && value !== null) {
        (obj as any)[prop] = sanitizeProperty(value, key, newValue);
      }
    }
  }

  return obj;
}

const sanitizeSarifOutput = (result: SarifReport): SarifReport => {
  const orderedArtifacts = orderBy(result.runs[0].artifacts, (item: SarifArtifact) => [item.location.uri, -item.location.uri]);
  result.runs[0].artifacts = orderedArtifacts;

  const orderedResults = orderBy(result.runs[0].results, (item: SarifResult) => [item.message.text, -item.message.text]);
  result.runs[0].results = orderedResults;

  const orderedLocations = orderBy(result.runs[0].results, (item: SarifResult) => [item.locations[0].physicalLocation.artifactLocation.uri, -item.locations[0]]);
  result.runs[0].results = orderedLocations;

  sanitizeProperty(result as unknown as SarifLocation, 'uri', 'somePath');
  sanitizeProperty(result, 'version', 'x.x.x');
  sanitizeProperty(result as unknown as SarifDriver, 'semanticVersion', 'x.x.x');
  sanitizeProperty(result as unknown as SarifDriver, 'fullName', 'cfn-guard x.x.x');

  return result;
};

export { sanitizeSarifOutput };
