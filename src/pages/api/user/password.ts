import { ObjectParser } from "@pilcrowjs/object-parser";
import { getUserPasswordHash, updateUserPassword } from "@lib/server/user";
import {
	verifyPasswordHash,
	verifyPasswordStrength,
	userUpdatePasswordRateLimit,
	ipPasswordHashRateLimit
} from "@lib/server/password";
import {
	createSession,
	generateSessionToken,
	invalidateUserSessions,
	setSessionTokenCookie
} from "@lib/server/session";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

export async function PATCH(context: APIContext): Promise<Response> {
	// TODO: Assumes X-Forwarded-For is always included.
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null && !ipPasswordHashRateLimit.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	if (context.locals.user === null || context.locals.session === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (!userUpdatePasswordRateLimit.check(context.locals.session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let password: string, newPassword: string;
	try {
		password = parser.getString("password");
		newPassword = parser.getString("new_password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	const strongPassword = await verifyPasswordStrength(newPassword);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	if (clientIP !== null && !ipPasswordHashRateLimit.consume(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!userUpdatePasswordRateLimit.consume(context.locals.session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const passwordHash = getUserPasswordHash(context.locals.user.id);
	const validPassword = await verifyPasswordHash(passwordHash, password);
	if (!validPassword) {
		return new Response("Incorrect password", {
			status: 400
		});
	}
	userUpdatePasswordRateLimit.reset(context.locals.session.userId);
	invalidateUserSessions(context.locals.user.id);
	await updateUserPassword(context.locals.user.id, newPassword);

	const sessionToken = generateSessionToken();
	const sessionFlags: SessionFlags = {
		twoFactorVerified: context.locals.session.twoFactorVerified
	};
	const session = createSession(sessionToken, context.locals.user.id, sessionFlags);
	setSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, { status: 204 });
}
