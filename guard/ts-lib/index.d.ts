export type SarifReport = {
    $schema: string;
    runs: SarifRun[];
    version: string;
};
export type SarifRun = {
    artifacts: SarifArtifact[];
    results: SarifResult[];
    tool: SarifTool;
};
export type SarifArtifact = {
    location: SarifLocation;
};
export type SarifLocation = {
    uri: string;
};
export type SarifResult = {
    level: string;
    locations: SarifPhysicalLocation[];
    message: SarifMessage;
    ruleId: string;
};
export type SarifPhysicalLocation = {
    physicalLocation: {
        artifactLocation: SarifArtifactLocation;
        region: SarifRegion;
    };
};
export type SarifArtifactLocation = {
    uri: string;
};
export type SarifRegion = {
    startColumn: number;
    startLine: number;
};
export type SarifMessage = {
    text: string;
};
export type SarifTool = {
    driver: SarifDriver;
};
export type SarifDriver = {
    downloadUri: string;
    fullName: string;
    informationUri: string;
    name: string;
    organization: string;
    semanticVersion: string;
    shortDescription: SarifShortDescription;
};
export type SarifShortDescription = {
    text: string;
};
type ValidateParams = {
    dataPath: string;
    rulesPath: string;
};
export declare const validate: ({ rulesPath, dataPath }: ValidateParams) => Promise<SarifReport>;
export {};
