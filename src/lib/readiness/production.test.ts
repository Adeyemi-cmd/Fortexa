import { Networks } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import {
  checkProductionReadiness,
  formatProductionReadinessReport,
  getProtectedPaymentFlowReadinessReport,
} from "@/lib/readiness/production";

const VALID_OPERATOR_WALLET =
  "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";

describe("production readiness", () => {
  it("passes for a valid production configuration", () => {
    const report = checkProductionReadiness(
      {
        NODE_ENV: "production",
        DATABASE_URL: "postgres://fortexa:secret@db.example.com:5432/fortexa",
        FORTEXA_AUTH_SECRET: "0123456789abcdef0123456789abcdef",
        FORTEXA_OPERATOR_WALLETS: VALID_OPERATOR_WALLET,
        FORTEXA_SHARED_STATE_PATH: "shared/security-state.json",
        STELLAR_HORIZON_URL: "https://horizon.stellar.org",
        STELLAR_NETWORK_PASSPHRASE: Networks.PUBLIC,
      },
      { cwd: "/srv/fortexa" }
    );

    expect(report.ok).toBe(true);
    expect(report.issues).toEqual([]);
  });

  it("reports missing required production variables", () => {
    const report = checkProductionReadiness(
      { NODE_ENV: "production" },
      { cwd: "/srv/fortexa" }
    );

    expect(report.ok).toBe(false);
    expect(report.issues.map((issue) => issue.setting)).toEqual(
      expect.arrayContaining([
        "STELLAR_HORIZON_URL",
        "STELLAR_NETWORK_PASSPHRASE",
        "FORTEXA_AUTH_SECRET",
        "FORTEXA_OPERATOR_WALLETS",
        "DATABASE_URL or FORTEXA_STORE_DIR",
        "REDIS_URL or FORTEXA_SHARED_STATE_PATH",
      ])
    );
  });

  it("rejects the wrong Stellar network passphrase for production", () => {
    const report = checkProductionReadiness(
      {
        NODE_ENV: "production",
        DATABASE_URL: "postgres://fortexa:secret@db.example.com:5432/fortexa",
        FORTEXA_AUTH_SECRET: "0123456789abcdef0123456789abcdef",
        FORTEXA_OPERATOR_WALLETS: VALID_OPERATOR_WALLET,
        FORTEXA_SHARED_STATE_PATH: "shared/security-state.json",
        STELLAR_HORIZON_URL: "https://horizon.stellar.org",
        STELLAR_NETWORK_PASSPHRASE: Networks.TESTNET,
      },
      { cwd: "/srv/fortexa" }
    );

    expect(report.ok).toBe(false);
    expect(report.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          setting: "STELLAR_NETWORK_PASSPHRASE",
        }),
      ])
    );
  });

  it("rejects missing storage backend configuration", () => {
    const report = checkProductionReadiness(
      {
        NODE_ENV: "production",
        FORTEXA_AUTH_SECRET: "0123456789abcdef0123456789abcdef",
        FORTEXA_OPERATOR_WALLETS: VALID_OPERATOR_WALLET,
        FORTEXA_SHARED_STATE_PATH: "shared/security-state.json",
        STELLAR_HORIZON_URL: "https://horizon.stellar.org",
        STELLAR_NETWORK_PASSPHRASE: Networks.PUBLIC,
      },
      { cwd: "/srv/fortexa" }
    );

    expect(report.ok).toBe(false);
    expect(report.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          setting: "DATABASE_URL or FORTEXA_STORE_DIR",
          message: expect.stringContaining("persistent storage backend"),
        }),
      ])
    );
  });

  it("rejects unsafe demo defaults for Horizon and file storage", () => {
    const report = checkProductionReadiness(
      {
        NODE_ENV: "production",
        FORTEXA_AUTH_SECRET: "0123456789abcdef0123456789abcdef",
        FORTEXA_OPERATOR_WALLETS: VALID_OPERATOR_WALLET,
        FORTEXA_SHARED_STATE_PATH: "shared/security-state.json",
        FORTEXA_STORE_DIR: ".fortexa",
        STELLAR_HORIZON_URL: "https://horizon-testnet.stellar.org",
        STELLAR_NETWORK_PASSPHRASE: Networks.PUBLIC,
      },
      { cwd: "/srv/fortexa" }
    );

    expect(report.ok).toBe(false);
    expect(report.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          setting: "STELLAR_HORIZON_URL",
          message: expect.stringContaining("Testnet Horizon"),
        }),
        expect.objectContaining({
          setting: "FORTEXA_STORE_DIR",
          message: expect.stringContaining("demo default"),
        }),
        expect.objectContaining({
          setting: "STELLAR_HORIZON_URL, STELLAR_NETWORK_PASSPHRASE",
        }),
      ])
    );
  });

  it("formats actionable output without exposing secret values", () => {
    const report = checkProductionReadiness(
      {
        NODE_ENV: "production",
        FORTEXA_AUTH_SECRET: "too-short-secret",
      },
      { cwd: "/srv/fortexa" }
    );

    const formatted = formatProductionReadinessReport(report);

    expect(formatted).toContain("FORTEXA_AUTH_SECRET");
    expect(formatted).not.toContain("too-short-secret");
  });

  it("only enforces payment-flow readiness in production", () => {
    const report = getProtectedPaymentFlowReadinessReport({
      NODE_ENV: "development",
    });

    expect(report).toBeNull();
  });
});
