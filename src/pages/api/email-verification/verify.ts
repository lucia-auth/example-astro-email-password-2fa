import {
	deleteSessionEmailVerificationRequest,
	deleteUserEmailVerificationRequests,
	getSessionEmailVerificationRequest,
	sessionEmailVerificationCounter
} from "@lib/server/email-verification";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { updateUserEmail } from "@lib/server/user";
import { invalidateUserPasswordResetSessions } from "@lib/server/password-reset";

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
		return new Response("Enter your code", {
			status: 400
		});
	}
	if (!sessionEmailVerificationCounter.increment(verificationRequest.sessionId)) {
		deleteSessionEmailVerificationRequest(verificationRequest.sessionId);
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (verificationRequest.code !== code) {
		return new Response("Incorrect code.", {
			status: 400
		});
	}
	deleteUserEmailVerificationRequests(context.locals.user.id);
	invalidateUserPasswordResetSessions(context.locals.user.id);
	updateUserEmail(context.locals.user.id, verificationRequest.email);
	return new Response(null, { status: 204 });
}
