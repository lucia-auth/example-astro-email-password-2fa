import { ObjectParser } from "@pilcrowjs/object-parser";
import { getUserPasswordHash, updateUserPassword } from "@lib/server/user";
import { verifyPasswordHash, verifyPasswordStrength } from "@lib/server/password";
import {
	createSession,
	generateSessionToken,
	invalidateUserSessions,
	setSessionTokenCookie
} from "@lib/server/session";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

export async function PATCH(context: APIContext): Promise<Response> {
	if (context.locals.user === null || context.locals.session === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (!context.locals.user.emailVerified) {
		return new Response(null, {
			status: 403
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 403
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
	const passwordHash = getUserPasswordHash(context.locals.user.id);
	const validPassword = await verifyPasswordHash(passwordHash, password);
	if (!validPassword) {
		return new Response("Incorrect password", {
			status: 400
		});
	}
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
