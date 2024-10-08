import {
	validatePasswordResetSessionRequest,
	setPasswordResetSessionAsEmailVerified
} from "@lib/server/password-reset";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { ExpiringTokenBucket } from "@lib/server/rate-limit";
import { setUserAsEmailVerifiedIfEmailMatches } from "@lib/server/user";

import type { APIContext } from "astro";

const bucket = new ExpiringTokenBucket<number>(5, 60 * 30);

export async function POST(context: APIContext): Promise<Response> {
	const { session } = validatePasswordResetSessionRequest(context);
	if (session === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (session.emailVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (!bucket.check(session.userId, 1)) {
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
	if (!bucket.consume(session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (code !== session.code) {
		return new Response("Incorrect code", {
			status: 400
		});
	}
	bucket.reset(session.userId);
	setPasswordResetSessionAsEmailVerified(session.id);
	const emailMatches = setUserAsEmailVerifiedIfEmailMatches(session.userId, session.email);
	if (!emailMatches) {
		return new Response("Please restart the process", {
			status: 400
		});
	}
	return new Response(null, { status: 204 });
}
