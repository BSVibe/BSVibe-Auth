import { describe, it, expect } from "vitest";
import { isConsentSkipEligible } from "./authorize_handler";

describe("isConsentSkipEligible", () => {
  it("allows the statically-seeded first-party clients", () => {
    expect(isConsentSkipEligible("claude-code-mcp")).toBe(true);
    expect(isConsentSkipEligible("cli")).toBe(true);
  });

  it("allows RFC 7591 dynamically-registered clients (dcr-* prefix)", () => {
    // Real Claude Code registers per-install via DCR and gets a dcr-*
    // client_id — it must skip the HTML consent page the MCP OAuth
    // driver cannot process (Round 5 dogfood bug).
    expect(isConsentSkipEligible("dcr-abc123")).toBe(true);
    expect(isConsentSkipEligible("dcr-")).toBe(true);
  });

  it("rejects unknown / third-party clients", () => {
    expect(isConsentSkipEligible("some-third-party")).toBe(false);
    expect(isConsentSkipEligible("")).toBe(false);
    // not a prefix match — must be at the start
    expect(isConsentSkipEligible("not-dcr-x")).toBe(false);
  });
});
