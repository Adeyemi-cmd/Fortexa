import { resetLocalDemoState } from './reset-local-demo-state';
import { NetworkConfig } from '../src/lib/stellar/network-config';
import { getDbPath, getStoragePaths } from '../src/lib/storage/paths';
import { rm, mkdir, writeFile } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';

// Mock the network config module
jest.mock('../src/lib/stellar/network-config', () => ({
  getNetworkConfig: jest.fn(),
}));

// Mock the storage paths module
jest.mock('../src/lib/storage/paths', () => ({
  getStoragePaths: jest.fn(),
  getDbPath: jest.fn(),
}));

// Mock process.exit
const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
  throw new Error('process.exit() called');
});

// Mock console.error
const mockConsoleError = jest.spyOn(console, 'error').mockImplementation();

describe('resetLocalDemoState', () => {
  const testDir = join(tmpdir(), 'fortexa-test-' + Date.now());
  const mockDataDir = join(testDir, 'data');
  const mockDbPath = join(testDir, 'db.sqlite');

  beforeEach(async () => {
    jest.clearAllMocks();
    await mkdir(testDir, { recursive: true });
    await mkdir(mockDataDir, { recursive: true });
    await writeFile(join(mockDataDir, 'test.txt'), 'test');
    await writeFile(mockDbPath, 'test');

    // Default mock for testnet
    require('../src/lib/stellar/network-config').getNetworkConfig.mockReturnValue({
      networkPassphrase: 'Test SDF Network ; September 2015',
    } as NetworkConfig);
    require('../src/lib/storage/paths').getStoragePaths.mockReturnValue({
      dataDir: mockDataDir,
    });
    require('../src/lib/storage/paths').getDbPath.mockReturnValue(mockDbPath);
  });

  afterEach(async () => {
    try {
      await rm(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it('should reset state for testnet fixture', async () => {
    await expect(resetLocalDemoState()).resolves.not.toThrow();
    expect(mockExit).not.toHaveBeenCalled();
    expect(mockConsoleError).not.toHaveBeenCalled();
  });

  it('should exit on production passphrase before any delete', async () => {
    require('../src/lib/stellar/network-config').getNetworkConfig.mockReturnValue({
      networkPassphrase: 'Standalone Network ; February 2017',
    } as NetworkConfig);

    await expect(resetLocalDemoState()).rejects.toThrow('process.exit() called');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(mockConsoleError).toHaveBeenCalledWith('Error: Reset aborted - production network detected');

    // Verify files were not deleted
    const files = await Promise.all([
      rm(mockDataDir, { recursive: true, force: true }).then(() => false).catch(() => true),
      rm(mockDbPath, { force: true }).then(() => false).catch(() => true),
    ]);
    expect(files.every(Boolean)).toBe(true);
  });

  it('should exit on unsupported passphrase', async () => {
    require('../src/lib/stellar/network-config').getNetworkConfig.mockReturnValue({
      networkPassphrase: 'Some other network',
    } as NetworkConfig);

    await expect(resetLocalDemoState()).rejects.toThrow('process.exit() called');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(mockConsoleError).toHaveBeenCalledWith('Error: Reset only supported for testnet fixture');
  });

  it('should not print secrets in error messages', async () => {
    const secretPassphrase = 'SuperSecretNetworkPassphrase123';
    require('../src/lib/stellar/network-config').getNetworkConfig.mockReturnValue({
      networkPassphrase: secretPassphrase,
    } as NetworkConfig);

    try {
      await resetLocalDemoState();
    } catch {
      // Expected to throw
    }

    expect(mockConsoleError.mock.calls.every(call => !call.some(arg => typeof arg === 'string' && arg.includes(secretPassphrase)))).toBe(true);
  });
});