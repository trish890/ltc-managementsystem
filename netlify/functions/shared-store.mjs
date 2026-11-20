import { sharedStore } from "../../db/store.ts";
import { createDecipheriv, pbkdf2, randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

export function createSharedStoreHandler(store) {
  const deriveKey = promisify(pbkdf2);
  const bundleKey = "shared-bundle";
  const maxBundleSize = 5 * 1024 * 1024;
  const sessionLifetime = 12 * 60 * 60 * 1000;
  const loginWindow = 15 * 60 * 1000;
  const loginLockDuration = 60 * 1000;
  const maxLoginAttempts = 5;
  const legacyVerifier = "e05f87b8ef2ef132283d94338331352fa5b8cb0402e00b865caceccf88fefbc8";

  function reply(body, status = 200) {
    return new Response(JSON.stringify(body), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  function decodeBase64(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
      throw new Error("Invalid encoded data");
    }
    return Buffer.from(value, "base64");
  }

  async function openWrappedKey(user, password) {
    const key = await deriveKey(
      Buffer.from(`${user.u.toLowerCase()}\n${password}`, "utf8"),
      decodeBase64(user.salt),
      150000,
      32,
      "sha256"
    );
    const wrapped = decodeBase64(user.wk);
    if (wrapped.length < 29) throw new Error("Invalid wrapped key");
    const decipher = createDecipheriv("aes-256-gcm", key, wrapped.subarray(0, 12));
    decipher.setAuthTag(wrapped.subarray(wrapped.length - 16));
    return Buffer.concat([
      decipher.update(wrapped.subarray(12, wrapped.length - 16)),
      decipher.final()
    ]);
  }

  function openEncryptedData(encoded, key) {
    const encrypted = decodeBase64(encoded);
    if (encrypted.length < 29) throw new Error("Invalid encrypted data");
    const decipher = createDecipheriv("aes-256-gcm", key, encrypted.subarray(0, 12));
    decipher.setAuthTag(encrypted.subarray(encrypted.length - 16));
    return JSON.parse(Buffer.concat([
      decipher.update(encrypted.subarray(12, encrypted.length - 16)),
      decipher.final()
    ]).toString("utf8"));
  }

  function validateUsers(users) {
    return users && users.v === 2 && Array.isArray(users.users) &&
      users.users.length > 0 &&
      users.users.length <= 500 &&
      users.users.every(user =>
        user && typeof user.id === "string" &&
        /^[a-z0-9._-]{3,24}$/.test(user.u) &&
        typeof user.salt === "string" &&
        typeof user.wk === "string"
      ) &&
      new Set(users.users.map(user => user.u)).size === users.users.length &&
      new Set(users.users.map(user => user.id)).size === users.users.length;
  }

  function validateProfiles(profiles) {
    const roles = new Set(["admin", "finance", "vp_operations", "executive_assistant"]);
    return Array.isArray(profiles) && profiles.length > 0 && profiles.length <= 500 &&
      profiles.every(profile =>
        profile && typeof profile.id === "string" &&
        /^[a-z0-9._-]{3,24}$/.test(profile.u) &&
        roles.has(profile.role) &&
        typeof profile.active === "boolean" &&
        typeof profile.legacyReadOnly === "boolean"
      ) &&
      new Set(profiles.map(profile => profile.id)).size === profiles.length &&
      new Set(profiles.map(profile => profile.u)).size === profiles.length;
  }

  function profilesMatchUsers(profiles, users) {
    if (!validateProfiles(profiles) || !validateUsers(users) ||
        profiles.length !== users.users.length) return false;
    const credentials = new Map(users.users.map(user => [user.id, user.u]));
    return profiles.every(profile => credentials.get(profile.id) === profile.u) &&
      profiles.some(profile => profile.role === "admin" && profile.active);
  }

  async function authenticate(bundle, username, password) {
    if (!validateUsers(bundle?.users) || typeof bundle.enc !== "string" ||
        typeof username !== "string" || username.length > 24 ||
        typeof password !== "string" || password.length > 1024) return null;
    const user = bundle.users.users.find(item => item.u === username.trim().toLowerCase());
    if (!user) return null;

    try {
      const key = await openWrappedKey(user, password);
      const data = openEncryptedData(bundle.enc, key);
      const member = data.team?.find(item => item.id === user.id);
      const profile = bundle.profiles
        ? bundle.profiles.find(item => item.id === user.id)
        : member && {
          id: member.id,
          u: member.u,
          role: member.role,
          active: !!member.active,
          legacyReadOnly: !!member.legacyReadOnly
        };
      if (!member || !profile || profile.u !== user.u || !profile.active) return null;
      return { user, member, profile, data, key };
    } catch {
      return null;
    }
  }

  async function hasLegacyAdminCredential(username, password) {
    const verifier = await deriveKey(
      Buffer.from(`${username}\n${password}`, "utf8"),
      Buffer.from("luwas-verify-v1", "utf8"),
      150000,
      32,
      "sha256"
    );
    return verifier.toString("hex") === legacyVerifier;
  }

  function matchesSetupKey(candidate) {
    const configured = process.env.LUWAS_SETUP_KEY;
    if (!configured || typeof candidate !== "string") return false;
    const supplied = Buffer.from(candidate, "utf8");
    const expected = Buffer.from(configured, "utf8");
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  }

  async function loginRateLimit(request, username) {
    const ip = request.headers.get("x-nf-client-connection-ip") || "unknown";
    const id = createHash("sha256").update(`${ip}\n${String(username).toLowerCase()}`).digest("hex");
    const key = `login-limit-${id}`;
    const state = await store.get(key, { type: "json" });
    if (state?.blockedUntil > Date.now()) return { key, blockedUntil: state.blockedUntil };
    if (!state || Date.now() - state.windowStarted > loginWindow) {
      return { key, count: 0, windowStarted: Date.now() };
    }
    return { ...state, key };
  }

  async function failedLogin(limit) {
    const count = limit.count + 1;
    const blockedUntil = count >= maxLoginAttempts ? Date.now() + loginLockDuration : 0;
    await store.setJSON(limit.key, {
      count: blockedUntil ? 0 : count,
      windowStarted: limit.windowStarted,
      blockedUntil
    });
    return blockedUntil;
  }

  function credentialDigest(user) {
    return createHash("sha256").update(`${user.u}\n${user.salt}\n${user.wk}`).digest("hex");
  }

  async function createSession(user, role) {
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    await store.setJSON(`session-${tokenHash}`, {
      userId: user.id,
      role,
      credentialDigest: credentialDigest(user),
      expiresAt: Date.now() + sessionLifetime
    });
    return token;
  }

  async function readSession(request) {
    const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
    if (!token || token.length > 128) return null;
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const session = await store.get(`session-${tokenHash}`, { type: "json" });
    if (!session || session.expiresAt <= Date.now()) return null;
    return {
      userId: session.userId,
      role: session.role,
      credentialDigest: session.credentialDigest,
      expiresAt: session.expiresAt,
      key: `session-${tokenHash}`
    };
  }

  async function readBody(request) {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > maxBundleSize + 64 * 1024) throw new Error("Request is too large");
    const text = await request.text();
    if (Buffer.byteLength(text, "utf8") > maxBundleSize + 64 * 1024) {
      throw new Error("Request is too large");
    }
    return JSON.parse(text);
  }

  async function initialize(request, body) {
    const limit = await loginRateLimit(request, body.username);
    if (limit.blockedUntil) {
      return reply({ error: "Too many sign-in attempts. Try again in one minute." }, 429);
    }
    if (await store.get(bundleKey, { type: "json" })) {
      return reply({ error: "Shared storage is already initialized." }, 409);
    }
    if (!validateUsers(body.users) || typeof body.enc !== "string" ||
        typeof body.username !== "string" || typeof body.password !== "string" ||
        Buffer.byteLength(body.enc, "utf8") > maxBundleSize) {
      return reply({ error: "The initial account data is invalid or too large." }, 400);
    }

    const bundle = { users: body.users, enc: body.enc, revision: 1 };
    const result = await authenticate(bundle, body.username, body.password);
    if (!result) {
      await failedLogin(limit);
      return reply({ error: "Only a valid active administrator can initialize shared storage." }, 403);
    }
    if (result.member.role !== "admin") {
      await failedLogin(limit);
      return reply({ error: "Only an Administrator can initialize shared storage.", code: "admin-required" }, 403);
    }
    if (!await hasLegacyAdminCredential(body.username, body.password) &&
        !matchesSetupKey(body.setupKey)) {
      await failedLogin(limit);
      return reply({
        error: "The original administrator password is no longer active. Configure LUWAS_SETUP_KEY in Netlify and enter it to initialize once.",
        code: "setup-key-required"
      }, 403);
    }

    bundle.profiles = result.data.team.map(member => ({
      id: member.id,
      u: member.u,
      role: member.role,
      active: !!member.active,
      legacyReadOnly: !!member.legacyReadOnly
    }));
    if (!profilesMatchUsers(bundle.profiles, bundle.users) ||
        !bundle.profiles.some(profile => profile.id === result.user.id && profile.role === "admin")) {
      return reply({ error: "The initial role information is invalid." }, 400);
    }
    if (!await store.createBundle(bundle)) {
      return reply({ error: "Shared storage was connected in another browser. Please sign in again." }, 409);
    }
    await store.delete(limit.key);
    const token = await createSession(result.user, result.profile.role);
    return reply({ initialized: true, token, profiles: bundle.profiles, revision: bundle.revision });
  }

  async function signIn(request, body) {
    const limit = await loginRateLimit(request, body.username);
    if (limit.blockedUntil) {
      return reply({ error: "Too many sign-in attempts. Try again in one minute." }, 429);
    }
    const bundle = await store.get(bundleKey, { type: "json" });
    if (!bundle) return reply({ initialized: false });

    const result = await authenticate(bundle, body.username, body.password);
    if (!result) {
      await failedLogin(limit);
      return reply({ error: "Incorrect username or password." }, 401);
    }

    await store.delete(limit.key);
    const token = await createSession(result.user, result.profile.role);
    return reply({
      initialized: true,
      token,
      users: result.profile.role === "admin"
        ? bundle.users
        : { v: 2, users: [result.user] },
      profiles: bundle.profiles,
      enc: bundle.enc,
      revision: bundle.revision
    });
  }

  async function updateBundle(request, body) {
    const session = await readSession(request);
    if (!session) return reply({ error: "Your session has expired. Please sign in again." }, 401);
    if (!validateUsers(body.users) || typeof body.enc !== "string" ||
        Buffer.byteLength(body.enc, "utf8") > maxBundleSize) {
      return reply({ error: "The shared data is invalid or too large." }, 400);
    }

    const current = await store.get(bundleKey, { type: "json" });
    if (!current) return reply({ error: "Shared storage has not been initialized." }, 409);
    if (!Number.isInteger(body.revision) || body.revision !== current.revision) {
      return reply({ error: "Another user saved changes after you opened this page. Reload before saving again." }, 409);
    }
    const oldUser = current.users.users.find(user => user.id === session.userId);
    const nextUser = body.users.users.find(user => user.id === session.userId);
    const currentProfile = current.profiles?.find(profile => profile.id === session.userId);
    if (!oldUser || !nextUser || session.credentialDigest !== credentialDigest(oldUser) || oldUser.u !== nextUser.u ||
        !currentProfile?.active || currentProfile.role !== session.role) {
      return reply({ error: "The signed-in account must remain active." }, 403);
    }

    let nextUsers = body.users;
    let nextProfiles = current.profiles;
    if (session.role !== "admin") {
      if (body.users.users.length !== 1) {
        return reply({ error: "Only an Administrator can manage user accounts." }, 403);
      }
      nextUsers = {
        v: 2,
        users: current.users.users.map(user => user.id === session.userId ? nextUser : user)
      };
    } else {
      if (!profilesMatchUsers(body.profiles, body.users)) {
        return reply({ error: "The role information is invalid or would remove the last active Administrator." }, 400);
      }
      nextProfiles = body.profiles;
    }

    const revision = current.revision + 1;
    // Keep this browser signed in after its own password change; other sessions are revoked.
    const refreshedSession = oldUser.salt !== nextUser.salt || oldUser.wk !== nextUser.wk
      ? { ...session, credentialDigest: credentialDigest(nextUser) }
      : undefined;
    if (!await store.updateBundle(current.revision, { users: nextUsers, profiles: nextProfiles, enc: body.enc, revision }, refreshedSession)) {
      return reply({ error: "Another user saved changes at the same time. Sign in again before retrying; your changes were not saved." }, 409);
    }
    return reply({ saved: true, revision });
  }

  return async function handler(request) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
    }

    try {
      if (request.method === "POST") {
        const body = await readBody(request);
        if (body.action === "login") return await signIn(request, body);
        if (body.action === "initialize") return await initialize(request, body);
        return reply({ error: "Unsupported request." }, 400);
      }
      if (request.method === "PUT") {
        return await updateBundle(request, await readBody(request));
      }
      if (request.method === "DELETE") {
        const session = await readSession(request);
        if (session) await store.delete(session.key);
        return reply({ signedOut: true });
      }
      return reply({ error: "Method not allowed." }, 405);
    } catch (error) {
      console.error("Shared-store request failed.");
      return reply({ error: "The shared storage service encountered an error." }, 500);
    }
  };
}

export default createSharedStoreHandler(sharedStore);
