import { rm } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const sharedStatePath = path.join(process.cwd(), ".nexusguard", "login-lockout-shared.test.json");

describe("login lockout shared state", () => {
  afterEach(async () => {
    delete process.env.NEXUSGUARD_SHARED_STATE_PATH;
    delete process.env.NEXUSGUARD_AUTH_MAX_ATTEMPTS;
    delete process.env.NEXUSGUARD_AUTH_LOCK_MINUTES;
    await rm(sharedStatePath, { force: true });
    vi.resetModules();
  });

  it("keeps lockout state across module reloads", async () => {
    process.env.NEXUSGUARD_SHARED_STATE_PATH = sharedStatePath;
    process.env.NEXUSGUARD_AUTH_MAX_ATTEMPTS = "2";
    process.env.NEXUSGUARD_AUTH_LOCK_MINUTES = "1";

    const firstModule = await import("@/lib/auth/login-lockout");
    await firstModule.resetLoginLockoutStore();
    await firstModule.registerLoginFailure("operator@nexusguard.local", "10.9.0.1");
    await firstModule.registerLoginFailure("operator@nexusguard.local", "10.9.0.1");

    expect((await firstModule.isLoginLocked("operator@nexusguard.local", "10.9.0.1")).locked).toBe(true);

    vi.resetModules();

    const secondModule = await import("@/lib/auth/login-lockout");
    const lockState = await secondModule.isLoginLocked("operator@nexusguard.local", "10.9.0.1");

    expect(lockState.locked).toBe(true);
    expect(lockState.retryAfterSeconds).toBeGreaterThan(0);
  });
});
