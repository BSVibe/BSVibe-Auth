import { describe, it, expect } from "vitest";
import { redirectUrisMatch } from "./authorization_code";

describe("redirectUrisMatch", () => {
  it("returns true on exact string equality", () => {
    expect(
      redirectUrisMatch(
        "https://app.example.com/callback",
        "https://app.example.com/callback",
      ),
    ).toBe(true);
  });

  it("treats 127.0.0.1 and localhost as interchangeable loopback hosts", () => {
    expect(
      redirectUrisMatch(
        "http://localhost:54321/callback",
        "http://127.0.0.1:54321/callback",
      ),
    ).toBe(true);
    expect(
      redirectUrisMatch(
        "http://127.0.0.1:54321/callback",
        "http://localhost:54321/callback",
      ),
    ).toBe(true);
  });

  it("treats [::1] as interchangeable with the IPv4 loopback hosts", () => {
    expect(
      redirectUrisMatch(
        "http://[::1]:54321/callback",
        "http://127.0.0.1:54321/callback",
      ),
    ).toBe(true);
  });

  it("requires the same port on loopback URIs", () => {
    expect(
      redirectUrisMatch(
        "http://localhost:54321/callback",
        "http://127.0.0.1:54322/callback",
      ),
    ).toBe(false);
  });

  it("requires the same path", () => {
    expect(
      redirectUrisMatch(
        "http://localhost:54321/callback",
        "http://127.0.0.1:54321/other",
      ),
    ).toBe(false);
  });

  it("requires the same protocol — https loopback is not http loopback", () => {
    expect(
      redirectUrisMatch(
        "https://localhost:54321/callback",
        "http://127.0.0.1:54321/callback",
      ),
    ).toBe(false);
  });

  it("requires the same query string", () => {
    expect(
      redirectUrisMatch(
        "http://localhost:54321/callback?x=1",
        "http://127.0.0.1:54321/callback?x=2",
      ),
    ).toBe(false);
  });

  it("rejects when only one side is a loopback host", () => {
    expect(
      redirectUrisMatch(
        "http://localhost:54321/callback",
        "http://attacker.example.com:54321/callback",
      ),
    ).toBe(false);
  });

  it("rejects when neither side is a loopback host even with same shape", () => {
    expect(
      redirectUrisMatch(
        "https://a.example.com/callback",
        "https://b.example.com/callback",
      ),
    ).toBe(false);
  });

  it("returns false on malformed URIs", () => {
    expect(redirectUrisMatch("not a url", "http://localhost/callback")).toBe(
      false,
    );
    expect(redirectUrisMatch("http://localhost/callback", "not a url")).toBe(
      false,
    );
  });
});
