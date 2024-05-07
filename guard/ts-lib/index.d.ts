export interface SarifReport {
    $schema: string;
    runs: SarifRun[];
    version: string;
}
export interface SarifRun {
    artifacts: SarifArtifact[];
    results: SarifResult[];
    tool: SarifTool;
}
export interface SarifArtifact {
    location: SarifLocation;
}
export interface SarifLocation {
    uri: string;
}
export interface SarifResult {
    level: string;
    locations: SarifPhysicalLocation[];
    message: SarifMessage;
    ruleId: string;
}
export interface SarifPhysicalLocation {
    physicalLocation: {
        artifactLocation: SarifArtifactLocation;
        region: SarifRegion;
    };
}
export interface SarifArtifactLocation {
    uri: string;
}
export interface SarifRegion {
    startColumn: number;
    startLine: number;
}
export interface SarifMessage {
    text: string;
}
export interface SarifTool {
    driver: SarifDriver;
}
export interface SarifDriver {
    downloadUri: string;
    fullName: string;
    informationUri: string;
    name: string;
    organization: string;
    semanticVersion: string;
    shortDescription: SarifShortDescription;
}
export interface SarifShortDescription {
    text: string;
}
interface ValidateParams {
    rulesPath: string;
    dataPath: string;
}
export declare const validate: ({ rulesPath, dataPath }: ValidateParams) => Promise<SarifReport>;
export {};
