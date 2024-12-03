import { ObjectParser } from "@pilcrowjs/object-parser";
import {
	createUserWithSignUpSession,
	deleteSignUpSessionTokenCookie,
	validateSignUpSessionRequest,
	signupSessionEmailVerificationCounter,
	invalidateSignUpSession
} from "@lib/server/signup-session";
import { createSession, generateSessionToken, setSessionTokenCookie } from "@lib/server/session";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

export async function POST(context: APIContext): Promise<Response> {
	const signupSession = validateSignUpSessionRequest(context);
	if (signupSession === null) {
		return new Response("Forbidden", {
			status: 401
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
	if (!signupSessionEmailVerificationCounter.increment(signupSession.id)) {
		invalidateSignUpSession(signupSession.id);
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (signupSession.emailVerificationCode !== code) {
		return new Response("Incorrect code.", {
			status: 400
		});
	}
	const user = createUserWithSignUpSession(signupSession.id);
	deleteSignUpSessionTokenCookie(context);
	const flags: SessionFlags = {
		twoFactorVerified: false
	};
	const sessionToken = generateSessionToken();
	const session = createSession(sessionToken, user.id, flags);
	setSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, { status: 204 });
}
