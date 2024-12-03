import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordStrength, ipPasswordHashRateLimit } from "@lib/server/password";
import { generateSessionToken } from "@lib/server/session";
import {
	createSignUpSession,
	ipSendSignUpVerificationEmailRateLimit,
	setSignUpSessionTokenCookie
} from "@lib/server/signup-session";
import { verifyUsernameInput } from "@lib/server/user";
import { checkEmailAvailability, verifyEmailInput } from "@lib/server/email";
import { sendVerificationEmail } from "@lib/server/email-verification";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	// TODO: Assumes X-Forwarded-For is always included.
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null && !ipPasswordHashRateLimit.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (clientIP !== null && ipSendSignUpVerificationEmailRateLimit.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string, username: string, password: string;
	try {
		email = parser.getString("email").toLowerCase();
		username = parser.getString("username");
		password = parser.getString("password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (email === "" || password === "" || username === "") {
		return new Response("Please enter your username, email, and password", {
			status: 400
		});
	}
	if (!verifyEmailInput(email)) {
		return new Response("Invalid email", {
			status: 400
		});
	}
	const emailAvailable = checkEmailAvailability(email);
	if (!emailAvailable) {
		return new Response("Email is already used", {
			status: 400
		});
	}
	if (!verifyUsernameInput(username)) {
		return new Response("Invalid username", {
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
	if (clientIP !== null && ipSendSignUpVerificationEmailRateLimit.consume(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const sessionToken = generateSessionToken();
	const session = await createSignUpSession(sessionToken, email, username, password);
	sendVerificationEmail(session.email, session.emailVerificationCode);

	setSignUpSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, { status: 204 });
}
