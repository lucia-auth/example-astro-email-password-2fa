import { ObjectParser } from "@pilcrowjs/object-parser";
import { ipPasswordHashRateLimit, verifyPasswordHash } from "@lib/server/password";
import { createSession, generateSessionToken, setSessionTokenCookie } from "@lib/server/session";
import { verifyEmailInput } from "@lib/server/email";
import { getUserFromEmail, getUserPasswordHash, userLoginRateLimit } from "@lib/server/user";
import { invalidateSession, deleteSessionTokenCookie } from "@lib/server/session";

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

	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string, password: string;
	try {
		email = parser.getString("email").toLowerCase();
		password = parser.getString("password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (email === "" || password === "") {
		return new Response("Please enter your email and password.", {
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
	if (clientIP !== null && !ipPasswordHashRateLimit.consume(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!userLoginRateLimit.consume(user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const passwordHash = getUserPasswordHash(user.id);
	const validPassword = await verifyPasswordHash(passwordHash, password);
	if (!validPassword) {
		return new Response("Invalid password", {
			status: 400
		});
	}
	userLoginRateLimit.reset(user.id);
	const sessionFlags: SessionFlags = {
		twoFactorVerified: false
	};
	const sessionToken = generateSessionToken();
	const session = createSession(sessionToken, user.id, sessionFlags);
	setSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, { status: 201 });
}

export async function DELETE(context: APIContext): Promise<Response> {
	if (context.locals.session === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	invalidateSession(context.locals.session.id);
	deleteSessionTokenCookie(context);
	return new Response(null, { status: 204 });
}
