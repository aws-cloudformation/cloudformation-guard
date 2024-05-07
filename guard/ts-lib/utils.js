"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeSarifOutput = void 0;
const orderBy = require('lodash/orderBy');
function sanitizeProperty(obj, key, newValue) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    for (const prop in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, prop)) {
            const value = obj[prop];
            if (prop === key && typeof value === 'string') {
                obj[prop] = newValue;
            }
            else if (typeof value === 'object' && value !== null) {
                obj[prop] = sanitizeProperty(value, key, newValue);
            }
        }
    }
    return obj;
}
const sanitizeSarifOutput = (result) => {
    const orderedArtifacts = orderBy(result.runs[0].artifacts, (item) => [item.location.uri, -item.location.uri]);
    result.runs[0].artifacts = orderedArtifacts;
    const orderedResults = orderBy(result.runs[0].results, (item) => [item.message.text, -item.message.text]);
    result.runs[0].results = orderedResults;
    const orderedLocations = orderBy(result.runs[0].results, (item) => [item.locations[0].physicalLocation.artifactLocation.uri, -item.locations[0]]);
    result.runs[0].results = orderedLocations;
    sanitizeProperty(result, 'uri', 'somePath');
    sanitizeProperty(result, 'version', 'x.x.x');
    sanitizeProperty(result, 'semanticVersion', 'x.x.x');
    sanitizeProperty(result, 'fullName', 'cfn-guard x.x.x');
    return result;
};
exports.sanitizeSarifOutput = sanitizeSarifOutput;
