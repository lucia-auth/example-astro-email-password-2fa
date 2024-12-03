import {
	validatePasswordResetSessionRequest,
	setPasswordResetSessionAsEmailVerified,
	userPasswordResetVerificationRateLimit,
	getPasswordResetSessionEmailVerificationCodeHash,
	invalidateUserPasswordResetSessions
} from "@lib/server/password-reset";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordHash } from "@lib/server/password";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	const { session } = validatePasswordResetSessionRequest(context);
	if (session === null) {
		return new Response("Please restart the process", {
			status: 401
		});
	}
	if (session.emailVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (!userPasswordResetVerificationRateLimit.check(session.userId, 1)) {
		invalidateUserPasswordResetSessions(session.userId);
		return new Response("Too many requests", {
			status: 429
		});
	}

	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let code: string;
	try {
		code = parser.getString("code");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (code === "") {
		return new Response("Please enter your code", {
			status: 400
		});
	}
	if (!userPasswordResetVerificationRateLimit.consume(session.userId, 1)) {
		invalidateUserPasswordResetSessions(session.userId);
		return new Response("Too many requests", {
			status: 429
		});
	}
	const hash = getPasswordResetSessionEmailVerificationCodeHash(session.id);
	if (hash === null) {
		return new Response("Unexpected error", {
			status: 500
		});
	}
	const validCode = await verifyPasswordHash(hash, code);
	if (!validCode) {
		return new Response("Incorrect code", {
			status: 400
		});
	}
	userPasswordResetVerificationRateLimit.reset(session.userId);
	setPasswordResetSessionAsEmailVerified(session.id);
	return new Response(null, { status: 204 });
}
