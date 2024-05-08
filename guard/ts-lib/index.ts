import { OutputFormatType, ShowSummaryType, ValidateBuilder } from './guard';
import * as path from 'node:path';
import * as fs from 'fs';

const DATA_FILE_SUPPORTED_EXTENSIONS = ['.yaml', '.yml', '.json', '.jsn', '.template'];
const RULE_FILE_SUPPORTED_EXTENSIONS = ['.guard', '.ruleset'];

type TraversalResult = {
  fileContents: string[];
  fileNames: string[];
}

type FormatOutputParams = {
  dataNames: string[];
  result: SarifReport;
  rulesNames: string[];
}

export type SarifReport = {
  $schema: string;
  runs: SarifRun[];
  version: string;
}

export type SarifRun = {
  artifacts: SarifArtifact[];
  results: SarifResult[];
  tool: SarifTool;
}

export type SarifArtifact = {
  location: SarifLocation;
}

export type SarifLocation = {
  uri: string;
}

export type SarifResult = {
  level: string;
  locations: SarifPhysicalLocation[];
  message: SarifMessage;
  ruleId: string;
}

export type SarifPhysicalLocation = {
  physicalLocation: {
    artifactLocation: SarifArtifactLocation;
    region: SarifRegion;
  };
}

export type SarifArtifactLocation = {
  uri: string;
}

export type SarifRegion = {
  startColumn: number;
  startLine: number;
}

export type SarifMessage = {
  text: string;
}

export type SarifTool = {
  driver: SarifDriver;
}

export type SarifDriver = {
  downloadUri: string;
  fullName: string;
  informationUri: string;
  name: string;
  organization: string;
  semanticVersion: string;
  shortDescription: SarifShortDescription;
}

export type SarifShortDescription = {
  text: string;
}

const formatOutput = ({ result, rulesNames, dataNames }: FormatOutputParams): SarifReport => {
  const dataPattern = /DATA_STDIN\[(\d+)\]/g;
  const rulesPattern = /RULES_STDIN\[(\d+)\]\/DEFAULT/g;

  const output = JSON.parse(JSON.stringify(result).replace(dataPattern, (match: string, index: string) => {
    const fileIndex = parseInt(index, 10) - 1;
    const fileName = dataNames[fileIndex];
    return fileName ? fileName.replace(/^\//, '') : match;
  }).replace(rulesPattern, (match: string, index: string) => {
    const ruleIndex = parseInt(index, 10) - 1;
    const ruleName = rulesNames[ruleIndex];
    if (ruleName) {
      const fileNameWithoutExtension = path.basename(ruleName, path.extname(ruleName));
      return fileNameWithoutExtension.toUpperCase();
    }
    return match;
  }));

  return JSON.parse(output);
}

  async function readFiles(dirPath: string, supportedExtensions: string[]): Promise<TraversalResult> {
    const fileNames: string[] = [];
    const fileContents: string[] = [];

    const files = await fs.promises.readdir(dirPath, { withFileTypes: true });
    const readPromises = files.map(async (file) => {
      const filePath = path.join(dirPath, file.name);
      if (!file.isDirectory() && supportedExtensions.includes(path.extname(filePath))) {
        const content = await fs.promises.readFile(filePath, 'utf8');
        fileNames.push(filePath);
        fileContents.push(content);
      }
    });
    await Promise.all(readPromises);

    return {
      fileContents,
      fileNames,
    };
  }

  type ValidateParams = {
    dataPath: string;
    rulesPath: string;
  }

export const validate = async ({ rulesPath, dataPath }: ValidateParams): Promise<SarifReport> => {
  const rulesResult = await readFiles(rulesPath, RULE_FILE_SUPPORTED_EXTENSIONS);
  const dataResult = await readFiles(dataPath, DATA_FILE_SUPPORTED_EXTENSIONS);

  const payload = {
    rules: rulesResult.fileContents,
    data: dataResult.fileContents,
  };

  const validateBuilder = new ValidateBuilder();
  const result: SarifReport = validateBuilder
    .payload(true)
    .structured(true)
    .showSummary([ShowSummaryType.None])
    .outputFormat(OutputFormatType.Sarif)
    .tryBuildAndExecute(JSON.stringify(payload));

  return formatOutput({
    result,
    rulesNames: rulesResult.fileNames,
    dataNames: dataResult.fileNames,
  });
}
