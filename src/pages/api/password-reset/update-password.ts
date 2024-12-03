import {
	deletePasswordResetSessionTokenCookie,
	invalidateUserPasswordResetSessions,
	validatePasswordResetSessionRequest
} from "@lib/server/password-reset";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { ipPasswordHashRateLimit, verifyPasswordStrength } from "@lib/server/password";
import { createSession, generateSessionToken, setSessionTokenCookie } from "@lib/server/session";
import { updateUserPassword } from "@lib/server/user";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

export async function POST(context: APIContext): Promise<Response> {
	// TODO: Assumes X-Forwarded-For is always included.
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null && !ipPasswordHashRateLimit.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	const { session: passwordResetSession, user } = validatePasswordResetSessionRequest(context);
	if (passwordResetSession === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (!passwordResetSession.emailVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (user.registered2FA && !passwordResetSession.twoFactorVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let password: string;
	try {
		password = parser.getString("password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	const strongPassword = await verifyPasswordStrength(password);
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
	invalidateUserPasswordResetSessions(passwordResetSession.userId);
	await updateUserPassword(passwordResetSession.userId, password);

	const sessionFlags: SessionFlags = {
		twoFactorVerified: passwordResetSession.twoFactorVerified
	};
	const sessionToken = generateSessionToken();
	const session = createSession(sessionToken, user.id, sessionFlags);
	setSessionTokenCookie(context, sessionToken, session.expiresAt);
	deletePasswordResetSessionTokenCookie(context);
	return new Response(null, {
		status: 204
	});
}
