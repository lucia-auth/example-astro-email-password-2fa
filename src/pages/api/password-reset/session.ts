import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyEmailInput } from "@lib/server/email";
import { getUserFromEmail } from "@lib/server/user";
import { ipPasswordHashRateLimit } from "@lib/server/password";
import {
	createPasswordResetSession,
	invalidateUserPasswordResetSessions,
	ipPasswordResetRateLimit,
	sendPasswordResetEmail,
	setPasswordResetSessionTokenCookie,
	userPasswordResetRateLimit
} from "@lib/server/password-reset";
import { generateSessionToken } from "@lib/server/session";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	// TODO: Assumes X-Forwarded-For is always included.
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null && !ipPasswordHashRateLimit.check(clientIP, 2)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (clientIP !== null && !ipPasswordResetRateLimit.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string;
	try {
		email = parser.getString("email").toLowerCase();
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (!verifyEmailInput(email)) {
		return new Response("Invalid email", {
			status: 400
		});
	}
	const user = getUserFromEmail(email);
	if (user === null) {
		return new Response("Account does not exist", {
			status: 400
		});
	}
	if (!userPasswordResetRateLimit.check(user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	if (clientIP !== null && !ipPasswordHashRateLimit.consume(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (clientIP !== null && !ipPasswordResetRateLimit.consume(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!userPasswordResetRateLimit.consume(user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	invalidateUserPasswordResetSessions(user.id);
	const sessionToken = generateSessionToken();
	const session = await createPasswordResetSession(sessionToken, user.id, user.email);
	sendPasswordResetEmail(session.email, session.emailVerificationCode);
	setPasswordResetSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, {
		status: 201
	});
}
