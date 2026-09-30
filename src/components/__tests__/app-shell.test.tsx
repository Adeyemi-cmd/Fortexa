import { render, screen } from '@testing-library/react';
import { AppShell } from '../app-shell';
import { getSessionRole } from '@/lib/auth/wallet-role';
import { getSession } from '@/lib/auth/session';

jest.mock('@/lib/auth/wallet-role');
jest.mock('@/lib/auth/session');
jest.mock('next/navigation', () => ({
  usePathname: () => '/',
}));

describe('AppShell navigation', () => {
  const mockGetSession = getSession as jest.MockedFunction<typeof getSession>;
  const mockGetSessionRole = getSessionRole as jest.MockedFunction<typeof getSessionRole>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows pay and hides policy for signer', () => {
    mockGetSession.mockReturnValue({} as any);
    mockGetSessionRole.mockReturnValue('signer');

    render(<AppShell>Test</AppShell>);

    expect(screen.getByText('Pay')).toBeInTheDocument();
    expect(screen.queryByText('Policy')).not.toBeInTheDocument();
  });

  it('shows policy and hides pay for operator', () => {
    mockGetSession.mockReturnValue({} as any);
    mockGetSessionRole.mockReturnValue('operator');

    render(<AppShell>Test</AppShell>);

    expect(screen.getByText('Policy')).toBeInTheDocument();
    expect(screen.queryByText('Pay')).not.toBeInTheDocument();
  });

  it('shows both pay and policy for dual-role', () => {
    mockGetSession.mockReturnValue({} as any);
    mockGetSessionRole.mockReturnValue('dual');

    render(<AppShell>Test</AppShell>);

    expect(screen.getByText('Pay')).toBeInTheDocument();
    expect(screen.getByText('Policy')).toBeInTheDocument();
  });

  it('hides both pay and policy when signed out', () => {
    mockGetSession.mockReturnValue(null);
    mockGetSessionRole.mockReturnValue(null);

    render(<AppShell>Test</AppShell>);

    expect(screen.queryByText('Pay')).not.toBeInTheDocument();
    expect(screen.queryByText('Policy')).not.toBeInTheDocument();
  });
});
