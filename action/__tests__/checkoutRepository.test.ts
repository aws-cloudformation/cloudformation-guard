import * as exec from '@actions/exec';
import { context } from '@actions/github';
import * as checkoutRepository from '../src/checkoutRepository';
import * as checkoutPrivateRepository from '../src/checkoutPrivateRepository';
import * as checkoutPublicRepository from '../src/checkoutPublicRepository';
import { describe, expect, jest, it, afterEach } from '@jest/globals';
import { GithubEventNames } from '../src/stringEnums';
import { ErrorStrings } from '../src/stringEnums';
import * as githubActions from '@actions/github';

describe('checkoutRepository', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should checkout the pull request ref for a public repository', async () => {
    context.eventName = GithubEventNames.PULL_REQUEST;

    jest.spyOn(exec, 'exec').mockImplementation(() => Promise.resolve(0));

    await checkoutRepository.checkoutRepository();

    expect(exec.exec).toHaveBeenCalledWith('git init');
    expect(exec.exec).toHaveBeenCalledWith(
      'git remote add origin https://github.com/owner/repo.git'
    );
    expect(exec.exec).toHaveBeenCalledWith(
      'git fetch origin refs/pull/123/merge'
    );
    expect(exec.exec).toHaveBeenCalledWith('git checkout -qf FETCH_HEAD');
  });

  it('should checkout the branch ref for a public repository', async () => {
    context.eventName = GithubEventNames.PUSH;

    jest.spyOn(exec, 'exec').mockImplementation(() => Promise.resolve(0));

    await checkoutRepository.checkoutRepository();

    expect(exec.exec).toHaveBeenCalledWith('git init');
    expect(exec.exec).toHaveBeenCalledWith(
      'git remote add origin https://github.com/owner/repo.git'
    );
    expect(exec.exec).toHaveBeenCalledWith('git fetch origin refs/heads/main');
    expect(exec.exec).toHaveBeenCalledWith('git checkout FETCH_HEAD');
  });

  it('should checkout the pull request ref for a private repository', async () => {
    context.eventName = GithubEventNames.PULL_REQUEST;
    jest.spyOn(githubActions, 'getOctokit').mockReturnValue({
      rest: {
        repos: {
          // @ts-ignore don't need a full repo get mock
          get: jest.fn().mockResolvedValue({ data: { private: true } } as never)
        }
      }
    });

    jest.spyOn(exec, 'exec').mockImplementation(() => Promise.resolve(0));
    jest
      .spyOn(checkoutPrivateRepository, 'checkoutPrivateRepository')
      .mockImplementation(() => Promise.resolve());

    await checkoutRepository.checkoutRepository();

    expect(
      checkoutPrivateRepository.checkoutPrivateRepository
    ).toHaveBeenCalled();
  });

  it('should checkout the branch ref for a private repository', async () => {
    context.eventName = GithubEventNames.PUSH;
    jest.spyOn(githubActions, 'getOctokit').mockReturnValue({
      rest: {
        repos: {
          // @ts-ignore don't need a full repo get mock
          get: jest.fn().mockResolvedValue({ data: { private: true } } as never)
        }
      }
    });
    jest.spyOn(exec, 'exec').mockImplementation(() => Promise.resolve(0));
    jest
      .spyOn(checkoutPrivateRepository, 'checkoutPrivateRepository')
      .mockImplementation(() => Promise.resolve());

    await checkoutRepository.checkoutRepository();

    expect(
      checkoutPrivateRepository.checkoutPrivateRepository
    ).toHaveBeenCalled();
  });

  it('should throw an error if the repository is not found', async () => {
    context.payload.repository = undefined;
    await expect(checkoutRepository.checkoutRepository()).rejects.toThrow(
      ErrorStrings.CHECKOUT_REPOSITORY_ERROR
    );
  });
});
