export interface AuditRow {
  id: string;
  timestamp: string;
  action: string;
  details: Record<string, unknown>;
  hash: string;
  previousHash: string;
}

export interface AuditPage {
  rows: AuditRow[];
  nextPage: number | null;
}
