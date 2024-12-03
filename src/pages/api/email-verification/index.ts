import { ObjectParser } from "@pilcrowjs/object-parser";
import {
	createSessionEmailVerificationRequest,
	userVerificationEmailRateLimit,
	sendVerificationEmail
} from "@lib/server/email-verification";
import { verifyEmailInput, checkEmailAvailability } from "@lib/server/email";

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
	if (!userVerificationEmailRateLimit.check(context.locals.user.id, 1)) {
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
	if (email === "") {
		return new Response("Please enter your email", {
			status: 400
		});
	}
	if (!verifyEmailInput(email)) {
		return new Response("Please enter a valid email", {
			status: 400
		});
	}
	const emailAvailable = checkEmailAvailability(email);
	if (!emailAvailable) {
		return new Response("This email is already used", {
			status: 400
		});
	}
	if (!userVerificationEmailRateLimit.consume(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const verificationRequest = createSessionEmailVerificationRequest(context.locals.session.id, email);
	sendVerificationEmail(verificationRequest.email, verificationRequest.code);
	return new Response(null, { status: 201 });
}
