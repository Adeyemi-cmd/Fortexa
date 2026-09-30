import { render, screen, fireEvent } from '@testing-library/react';
import { WalletStatusCard } from './wallet-status-card';
import { useWallet } from '@solana/wallet-adapter-react';
import { useSessionWallet } from '@/lib/auth/session-wallet';
import { useWalletRole } from '@/lib/auth/wallet-role';
import { PublicKey } from '@solana/web3.js';

jest.mock('@solana/wallet-adapter-react');
jest.mock('@/lib/auth/session-wallet');
jest.mock('@/lib/auth/wallet-role');

const mockUseWallet = useWallet as jest.MockedFunction<typeof useWallet>;
const mockUseSessionWallet = useSessionWallet as jest.MockedFunction<typeof useSessionWallet>;
const mockUseWalletRole = useWalletRole as jest.MockedFunction<typeof useWalletRole>;

const mockPublicKey = new PublicKey('11111111111111111111111111111111');
const mockSessionKey = new PublicKey('22222222222222222222222222222222');

const mockOnPay = jest.fn();
const mockOnPolicy = jest.fn();
const mockOnRevoke = jest.fn();
const mockClearSession = jest.fn();

describe('WalletStatusCard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows signed out when not connected', () => {
    mockUseWallet.mockReturnValue({ connected: false, publicKey: null });
    mockUseSessionWallet.mockReturnValue({ sessionWallet: null, clearSession: mockClearSession });
    mockUseWalletRole.mockReturnValue({ hasPayRole: false, hasPolicyRole: false });

    render(
      <WalletStatusCard
        onPay={mockOnPay}
        onPolicy={mockOnPolicy}
        onRevoke={mockOnRevoke}
      />
    );

    expect(screen.getByText('Wallet not connected')).toBeInTheDocument();
  });

  it('enables actions when wallet matches session', () => {
    mockUseWallet.mockReturnValue({ connected: true, publicKey: mockPublicKey });
    mockUseSessionWallet.mockReturnValue({ sessionWallet: mockPublicKey, clearSession: mockClearSession });
    mockUseWalletRole.mockReturnValue({ hasPayRole: true, hasPolicyRole: true });

    render(
      <WalletStatusCard
        onPay={mockOnPay}
        onPolicy={mockOnPolicy}
        onRevoke={mockOnRevoke}
      />
    );

    expect(screen.getByText('Pay')).not.toBeDisabled();
    expect(screen.getByText('Policy')).not.toBeDisabled();
    expect(screen.queryByText('Session wallet mismatch')).not.toBeInTheDocument();
  });

  it('disables actions when wallet does not match session', () => {
    mockUseWallet.mockReturnValue({ connected: true, publicKey: mockPublicKey });
    mockUseSessionWallet.mockReturnValue({ sessionWallet: mockSessionKey, clearSession: mockClearSession });
    mockUseWalletRole.mockReturnValue({ hasPayRole: true, hasPolicyRole: true });

    render(
      <WalletStatusCard
        onPay={mockOnPay}
        onPolicy={mockOnPolicy}
        onRevoke={mockOnRevoke}
      />
    );

    expect(screen.getByText('Pay')).toBeDisabled();
    expect(screen.getByText('Policy')).toBeDisabled();
    expect(screen.getByText('Session wallet mismatch')).toBeInTheDocument();
  });

  it('clears session on revoke', () => {
    mockUseWallet.mockReturnValue({ connected: true, publicKey: mockPublicKey });
    mockUseSessionWallet.mockReturnValue({ sessionWallet: mockPublicKey, clearSession: mockClearSession });
    mockUseWalletRole.mockReturnValue({ hasPayRole: true, hasPolicyRole: true });

    render(
      <WalletStatusCard
        onPay={mockOnPay}
        onPolicy={mockOnPolicy}
        onRevoke={mockOnRevoke}
      />
    );

    fireEvent.click(screen.getByText('Revoke'));
    expect(mockOnRevoke).toHaveBeenCalled();
    expect(mockClearSession).toHaveBeenCalled();
  });

  it('disables actions when roles are missing even with matching wallet', () => {
    mockUseWallet.mockReturnValue({ connected: true, publicKey: mockPublicKey });
    mockUseSessionWallet.mockReturnValue({ sessionWallet: mockPublicKey, clearSession: mockClearSession });
    mockUseWalletRole.mockReturnValue({ hasPayRole: false, hasPolicyRole: false });

    render(
      <WalletStatusCard
        onPay={mockOnPay}
        onPolicy={mockOnPolicy}
        onRevoke={mockOnRevoke}
      />
    );

    expect(screen.getByText('Pay')).toBeDisabled();
    expect(screen.getByText('Policy')).toBeDisabled();
  });
});
