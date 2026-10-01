'use client';

import { useState, useEffect } from 'react';
import { verifyHashChain } from '@/lib/audit/hash-chain';
import { redactSecrets } from '@/lib/audit/redact';

interface AuditRow {
  id: string;
  timestamp: string;
  action: string;
  details: Record<string, unknown>;
  hash: string;
  previousHash: string;
}

interface AuditPage {
  rows: AuditRow[];
  nextPage: number | null;
}

interface ActivityTimelineProps {
  initialPages: AuditPage[];
}

export function ActivityTimeline({ initialPages }: ActivityTimelineProps) {
  const [pages, setPages] = useState<AuditPage[]>(initialPages);
  const [isLoading, setIsLoading] = useState(false);
  const [hasBrokenChain, setHasBrokenChain] = useState(false);
  const [visibleRows, setVisibleRows] = useState<AuditRow[]>([]);

  useEffect(() => {
    processPages(initialPages);
  }, []);

  const processPages = (newPages: AuditPage[]) => {
    const allRows: AuditRow[] = [];
    let chainBroken = false;

    for (const page of newPages) {
      if (chainBroken) break;

      const processedRows: AuditRow[] = [];
      for (const row of page.rows) {
        if (chainBroken) break;

        // Verify hash chain integrity
        if (allRows.length > 0) {
          const lastRow = allRows[allRows.length - 1];
          if (row.previousHash !== lastRow.hash) {
            chainBroken = true;
            setHasBrokenChain(true);
            break;
          }
        }

        // Redact secrets before adding to visible rows
        const redactedRow = redactSecrets(row);
        processedRows.push(redactedRow);
      }

      if (!chainBroken) {
        allRows.push(...processedRows);
      }
    }

    setVisibleRows(allRows);
  };

  const loadNextPage = async () => {
    if (isLoading || hasBrokenChain) return;

    const lastPage = pages[pages.length - 1];
    if (!lastPage.nextPage) return;

    setIsLoading(true);
    try {
      const response = await fetch(`/api/audit?page=${lastPage.nextPage}`);
      const nextPage: AuditPage = await response.json();
      
      // Verify the new page's hash chain before adding
      const newPages = [...pages, nextPage];
      
      // Check if the chain is broken between last page and new page
      if (pages.length > 0 && nextPage.rows.length > 0) {
        const lastRow = pages[pages.length - 1].rows[pages[pages.length - 1].rows.length - 1];
        const firstNewRow = nextPage.rows[0];
        
        if (firstNewRow.previousHash !== lastRow.hash) {
          setHasBrokenChain(true);
          setPages(newPages);
          processPages(newPages);
          return;
        }
      }
      
      setPages(newPages);
      processPages(newPages);
    } catch (error) {
      console.error('Failed to load next page:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {visibleRows.map((row) => (
              <tr key={row.id} className={hasBrokenChain ? 'opacity-50' : ''}>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{row.timestamp}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{row.action}</td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  <pre className="text-xs">{JSON.stringify(row.details, null, 2)}</pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {!hasBrokenChain && pages[pages.length - 1]?.nextPage && (
        <div className="flex justify-center mt-4">
          <button
            onClick={loadNextPage}
            disabled={isLoading}
            className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {isLoading ? 'Loading...' : 'Load More'}
          </button>
        </div>
      )}
      
      {hasBrokenChain && (
        <div className="text-center text-red-500 text-sm mt-4">
          Hash chain broken. No further pages will be loaded.
        </div>
      )}
    </div>
  );
}