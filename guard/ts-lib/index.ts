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
  // Present only when the run has something to say about itself, such as a
  // rules file that could not be parsed. A run whose `results` are empty is a
  // clean run only if no invocation reports `executionSuccessful: false`.
  invocations?: SarifInvocation[];
  results: SarifResult[];
  tool: SarifTool;
}

export type SarifInvocation = {
  executionSuccessful: boolean;
  toolConfigurationNotifications?: SarifNotification[];
}

export type SarifNotification = {
  level: string;
  message: SarifMessage;
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
    // Absent when the position of the finding is not known. The core omits the
    // region rather than reporting line 1 for a position it does not have.
    region?: SarifRegion;
  };
}

export type SarifArtifactLocation = {
  uri: string;
}

export type SarifRegion = {
  // Absent when the line is known and the column is not.
  startColumn?: number;
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

type ValidateParams = {
  dataPath: string;
  rulesPath: string;
}

const formatOutput = ({ result, rulesNames, dataNames }: FormatOutputParams): SarifReport => {
  const dataPattern = /DATA_STDIN\[(\d+)\]/g;
  const rulesPattern = /RULES_STDIN\[(\d+)\]\/DEFAULT/g;
  // The core names a rules file it was given through the payload RULES_STDIN[n] wherever it
  // mentions it, including the notification for a file that did not parse. After the ruleId pass
  // above, any remaining mention gets the file name the caller supplied.
  const rulesFilePattern = /RULES_STDIN\[(\d+)\]/g;
  const isWindows = process.platform === 'win32';

  const output = JSON.parse(JSON.stringify(result).replace(dataPattern, (match: string, index: string) => {
    const fileIndex = parseInt(index, 10) - 1;
    const fileName = dataNames[fileIndex];

    return fileName ? (isWindows ? fileName.split('\\').join('/') : fileName) : match;
  }).replace(rulesPattern, (match: string, index: string) => {
    const ruleIndex = parseInt(index, 10) - 1;
    const ruleName = rulesNames[ruleIndex];
    if (ruleName) {
      const fileNameWithoutExtension = path.basename(ruleName, path.extname(ruleName));
      return fileNameWithoutExtension.toUpperCase();
    }
    return match;
  }).replace(rulesFilePattern, (match: string, index: string) => {
    const ruleIndex = parseInt(index, 10) - 1;
    const ruleName = rulesNames[ruleIndex];

    // The substitution happens inside a JSON-encoded string, so a Windows path separator has to
    // become `/` here as it does for data names above.
    return ruleName ? (isWindows ? ruleName.split('\\').join('/') : ruleName) : match;
  }));

  return JSON.parse(output);
};

async function readFiles(dirOrFile: string, supportedExtensions: string[]): Promise<TraversalResult> {
  const fileNames: string[] = [];
  const fileContents: string[] = [];

  const stat = await fs.promises.stat(dirOrFile);

  if (stat.isDirectory()) {
    const files = await getAllFiles(dirOrFile, supportedExtensions);
    const readPromises = files.map(async (file) => {
      const content = await fs.promises.readFile(file, 'utf8');
      fileNames.push(file);
      fileContents.push(content);
    });
    await Promise.all(readPromises);
  } else if (stat.isFile() && supportedExtensions.includes(path.extname(dirOrFile))) {
    const content = await fs.promises.readFile(dirOrFile, 'utf8');
    fileNames.push(dirOrFile);
    fileContents.push(content);
  }

  return {
    fileContents,
    fileNames,
  };
}

async function getAllFiles(dirPath: string, supportedExtensions: string[]): Promise<string[]> {
  const files: string[] = [];

  const dirEntries = await fs.promises.readdir(dirPath, { withFileTypes: true });
  const traversalPromises = dirEntries.map(async (entry) => {
    const entryPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      const subFiles = await getAllFiles(entryPath, supportedExtensions);
      files.push(...subFiles);
    } else if (supportedExtensions.includes(path.extname(entryPath))) {
      files.push(entryPath);
    }
  });
  await Promise.all(traversalPromises);

  return files;
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
