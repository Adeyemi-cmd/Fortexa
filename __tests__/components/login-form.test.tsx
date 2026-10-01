import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LoginForm from '@/components/login-form';
import { getChallenge } from '@/app/api/auth/challenge/route';
import { signChallenge } from '@/lib/auth/wallet-challenge';

// Mock the API calls
jest.mock('@/app/api/auth/challenge/route');
jest.mock('@/lib/auth/wallet-challenge');

describe('LoginForm', () => {
  const mockGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
  const mockSignChallenge = signChallenge as jest.MockedFunction<typeof signChallenge>;

  beforeEach(() => {
    mockGetChallenge.mockResolvedValue('test-challenge');
    mockSignChallenge.mockResolvedValue('test-signature');
    global.fetch = jest.fn() as jest.MockedFunction<typeof fetch>;
  });

  it('fetches new challenge on each submit', async () => {
    render(<LoginForm />);

    // First submit
    fireEvent.click(screen.getByText('Login with Wallet'));
    await waitFor(() => expect(mockGetChallenge).toHaveBeenCalledTimes(1));

    // Second submit
    fireEvent.click(screen.getByText('Login with Wallet'));
    await waitFor(() => expect(mockGetChallenge).toHaveBeenCalledTimes(2));
  });

  it('clears challenge after failed login', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({ code: 'LOGIN_FAILED' }),
    });

    render(<LoginForm />);
    fireEvent.click(screen.getByText('Login with Wallet'));

    await waitFor(() => {
      expect(screen.getByText('LOGIN_FAILED')).toBeInTheDocument();
      expect(mockGetChallenge).toHaveBeenCalledTimes(1);
    });
  });

  it('does not show signed payload in error', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({ code: 'INVALID_SIGNATURE' }),
    });

    render(<LoginForm />);
    fireEvent.click(screen.getByText('Login with Wallet'));

    await waitFor(() => {
      expect(screen.getByText('INVALID_SIGNATURE')).toBeInTheDocument();
      expect(screen.queryByText(/test-signature/)).not.toBeInTheDocument();
    });
  });
});
