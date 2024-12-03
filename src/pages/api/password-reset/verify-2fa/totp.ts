import { verifyTOTP } from "@oslojs/otp";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { getUserTOTPKey } from "@lib/server/user";
import { validatePasswordResetSessionRequest, setPasswordResetSessionAs2FAVerified } from "@lib/server/password-reset";
import { userTOTPVerificationRateLimit } from "@lib/server/2fa";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	const { session, user } = validatePasswordResetSessionRequest(context);
	if (session === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (!session.emailVerified || !user.registered2FA || session.twoFactorVerified) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (!userTOTPVerificationRateLimit.check(session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}

	const data: unknown = await context.request.json();
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
	const totpKey = getUserTOTPKey(session.userId);
	if (totpKey === null) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (!userTOTPVerificationRateLimit.consume(session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!verifyTOTP(totpKey, 30, 6, code)) {
		return new Response("Invalid code", {
			status: 400
		});
	}
	userTOTPVerificationRateLimit.reset(session.userId);
	setPasswordResetSessionAs2FAVerified(session.id);
	return new Response(null, { status: 204 });
}
