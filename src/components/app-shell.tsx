import { type ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { getSessionRole } from '@/lib/auth/wallet-role';
import { getSession } from '@/lib/auth/session';

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const session = getSession();
  const role = getSessionRole();

  const showPay = role === 'signer' || role === 'dual';
  const showPolicy = role === 'operator' || role === 'dual';
  const hasSession = !!session;

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-gray-200 bg-white sticky top-0 z-10">
        <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Link href="/" className="text-xl font-bold text-gray-900">
                Fortexa
              </Link>
            </div>
            <div className="flex items-center space-x-8">
              <Link
                href="/"
                className={`text-sm font-medium ${
                  pathname === '/' ? 'text-indigo-600' : 'text-gray-500 hover:text-gray-900'
                }`}
              >
                Dashboard
              </Link>
              {showPay && hasSession && (
                <Link
                  href="/pay"
                  prefetch={false}
                  className={`text-sm font-medium ${
                    pathname.startsWith('/pay')
                      ? 'text-indigo-600'
                      : 'text-gray-500 hover:text-gray-900'
                  }`}
                >
                  Pay
                </Link>
              )}
              {showPolicy && hasSession && (
                <Link
                  href="/policy"
                  prefetch={false}
                  className={`text-sm font-medium ${
                    pathname.startsWith('/policy')
                      ? 'text-indigo-600'
                      : 'text-gray-500 hover:text-gray-900'
                  }`}
                >
                  Policy
                </Link>
              )}
            </div>
          </div>
        </nav>
      </header>
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}
