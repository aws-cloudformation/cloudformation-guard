import { context } from '@actions/github';
import { jest } from '@jest/globals';

context.eventName = 'pull_request';
context.sha = 'test-sha';
context.payload = {
  ref: 'refs/heads/main',
  pull_request: {
    number: 123,
    head: {
      sha: 'sha'
    }
  },
  head_commit: {
    id: 'test-commit-id'
  },
  repository: {
    full_name: 'owner/repo',
    name: 'repo',
    owner: {
      login: 'owner'
    }
  },
  sha: 'test-sha'
};

jest.mock('@actions/exec', () => {
  const originalModule = jest.requireActual('@actions/exec') as Object;

  return {
    __esModule: true,
    ...originalModule,
    exec: jest.fn()
  };
});

jest.mock('@actions/github', () => {
  const originalModule = jest.requireActual('@actions/github') as Object;

  return {
    __esModule: true,
    ...originalModule,
    context: {
      eventName: 'pull_request',
      payload: {
        pull_request: {
          number: 123
        }
      },
      repo: {
        owner: 'owner',
        repo: 'repo'
      }
    },
    getOctokit: jest.fn().mockReturnValue({
      rest: {
        repos: {
          get: jest.fn().mockResolvedValue({
            data: {
              content: 'test-content'
            }
          } as never)
        },
        pulls: {
          listFiles: jest.fn().mockResolvedValue({
            data: [
              { filename: 'file1.yaml' },
              { filename: 'file2.yaml' },
              { filename: 'file3.yaml' }
            ]
          } as never),
          createReview: jest.fn()
        }
      },
      request: jest.fn().mockReturnValue({ data: [] })
    })
  };
});

jest.mock('@actions/core', () => {
  const originalModule = jest.requireActual('@actions/core') as Object;

  return {
    __esModule: true,
    ...originalModule,
    getInput: jest.fn().mockImplementation(name => {
      switch (name) {
        case 'rules':
          return 'test-rules-path';
        case 'data':
          return 'test-data-path';
        case 'token':
          return 'test-token';
        case 'path':
          return '';
        default:
          return '';
      }
    }),
    getBooleanInput: jest.fn().mockImplementation(name => {
      switch (name) {
        case 'checkout':
          return true;
        case 'analyze':
          return true;
        case 'create-review':
          return true;
        case 'debug':
          return false;
        default:
          return false;
      }
    }),
    setOutput: jest.fn(),
    setFailed: jest.fn()
  };
});
