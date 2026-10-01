import { render, screen, fireEvent } from '@testing-library/react';
import { ActivityTimeline } from '@/components/activity-timeline';
import { redactSecrets } from '@/lib/audit/redact';

// Mock data
const mockPages = [
  {
    rows: [
      {
        id: '1',
        timestamp: '2026-09-30T10:00:00Z',
        action: 'login',
        details: { user: 'alice' },
        hash: 'a1b2c3',
        previousHash: ''
      },
      {
        id: '2',
        timestamp: '2026-09-30T10:05:00Z',
        action: 'update',
        details: { field: 'profile', secret: 'sensitive-data' },
        hash: 'd4e5f6',
        previousHash: 'a1b2c3'
      }
    ],
    nextPage: 1
  },
  {
    rows: [
      {
        id: '3',
        timestamp: '2026-09-30T10:10:00Z',
        action: 'delete',
        details: { item: 'document' },
        hash: 'g7h8i9',
        previousHash: 'd4e5f6'
      },
      {
        id: '4',
        timestamp: '2026-09-30T10:15:00Z',
        action: 'create',
        details: { type: 'note' },
        hash: 'j0k1l2',
        previousHash: 'WRONG_HASH' // Broken chain
      }
    ],
    nextPage: 2
  }
];

// Mock fetch for loading next page
beforeEach(() => {
  global.fetch = jest.fn((url) => {
    if (url.includes('page=1')) {
      return Promise.resolve({
        json: () => Promise.resolve(mockPages[1])
      });
    }
    return Promise.reject(new Error('Unexpected URL'));
  });
});

describe('ActivityTimeline', () => {
  it('renders initial rows correctly', () => {
    render(<ActivityTimeline initialPages={[mockPages[0]]} />);
    
    expect(screen.getByText('login')).toBeInTheDocument();
    expect(screen.getByText('update')).toBeInTheDocument();
    expect(screen.getByText('Load More')).toBeInTheDocument();
  });

  it('redacts secret fields in rendered rows', () => {
    render(<ActivityTimeline initialPages={[mockPages[0]]} />);
    
    // The secret field should be redacted in the rendered output
    const preElements = screen.getAllByText(/\{[\s\S]*\}/);
    const detailsText = preElements[1].textContent;
    expect(detailsText).not.toContain('sensitive-data');
    expect(detailsText).toContain('[REDACTED]');
  });

  it('stops loading after broken hash chain', async () => {
    render(<ActivityTimeline initialPages={[mockPages[0]]} />);
    
    // Click load more to get the page with broken chain
    const loadMoreButton = screen.getByText('Load More');
    fireEvent.click(loadMoreButton);
    
    // Wait for the next page to load
    await screen.findByText('delete');
    
    // The broken chain message should appear
    expect(await screen.findByText(/Hash chain broken/)).toBeInTheDocument();
    
    // The Load More button should be gone
    expect(screen.queryByText('Load More')).not.toBeInTheDocument();
    
    // The row after the break should not be visible
    expect(screen.queryByText('create')).not.toBeInTheDocument();
  });

  it('does not request next page after break', async () => {
    render(<ActivityTimeline initialPages={[mockPages[0], mockPages[1]]} />);
    
    // The broken chain should be detected immediately
    expect(await screen.findByText(/Hash chain broken/)).toBeInTheDocument();
    
    // No additional fetch calls should be made
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('redactSecrets', () => {
  it('redacts known secret fields', () => {
    const row = {
      id: '1',
      timestamp: '2026-09-30T10:00:00Z',
      action: 'test',
      details: {
        user: 'alice',
        secret: 'should-be-redacted',
        nested: {
          apiKey: 'also-secret',
          public: 'visible'
        }
      },
      hash: 'abc',
      previousHash: ''
    };

    const redacted = redactSecrets(row);
    
    expect(redacted.details).toEqual({
      user: 'alice',
      secret: '[REDACTED]',
      nested: {
        apiKey: '[REDACTED]',
        public: 'visible'
      }
    });
  });
});
