import { context } from '@actions/github';

context.eventName = 'pull_request';
context.payload = {
  ref: 'refs/heads/main',
  pull_request: {
    number: 123
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
  }
};

jest.mock('@actions/exec', () => {
  const originalModule = jest.requireActual('@actions/exec');

  return {
    __esModule: true,
    ...originalModule,
    exec: jest.fn()
  };
});

jest.mock('@actions/github', () => {
  const originalModule = jest.requireActual('@actions/github');

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
        pulls: {
          listFiles: jest.fn().mockResolvedValue({
            data: [
              { filename: 'file1.yaml' },
              { filename: 'file2.yaml' },
              { filename: 'file3.yaml' }
            ]
          }),
          createReview: jest.fn()
        }
      }
    })
  };
});

jest.mock('@actions/core', () => {
  const originalModule = jest.requireActual('@actions/core');

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
        default:
          return false;
      }
    }),
    setOutput: jest.fn(),
    setFailed: jest.fn()
  };
});
