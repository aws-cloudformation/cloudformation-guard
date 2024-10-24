/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  modulePathIgnorePatterns: [
    "<rootDir>/dist/",
    "<rootDir>/node_modules/",
    "<rootDir>/lib/",
  ],
  transform: {
    "^.+\\.ts?$": [
      "ts-jest",
      {
        diagnostics: false,
      },
    ],
  },
};
