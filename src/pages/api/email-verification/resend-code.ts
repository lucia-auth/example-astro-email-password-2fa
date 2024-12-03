import {
	getSessionEmailVerificationRequest,
	sendVerificationEmail,
	userVerificationEmailRateLimit
} from "@lib/server/email-verification";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null || context.locals.user === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}

	const verificationRequest = getSessionEmailVerificationRequest(context.locals.session.id);
	if (verificationRequest === null) {
		return new Response("Forbidden", {
			status: 403
		});
	}

	if (!userVerificationEmailRateLimit.consume(context.locals.session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	sendVerificationEmail(verificationRequest.email, verificationRequest.code);
	return new Response(null, {
		status: 201
	});
}
