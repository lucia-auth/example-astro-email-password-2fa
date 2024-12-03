import { sendVerificationEmail } from "@lib/server/email-verification";
import { ipSendSignUpVerificationEmailRateLimit, validateSignUpSessionRequest } from "@lib/server/signup-session";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	const clientIP = context.request.headers.get("X-Forwarded-For");

	const session = validateSignUpSessionRequest(context);
	if (session === null) {
		return new Response("Forbidden", {
			status: 401
		});
	}

	if (clientIP !== null && !ipSendSignUpVerificationEmailRateLimit.consume(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	sendVerificationEmail(session.email, session.emailVerificationCode);
	return new Response(null, {
		status: 201
	});
}
