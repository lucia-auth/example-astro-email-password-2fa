import { ObjectParser } from "@pilcrowjs/object-parser";
import { userRecoveryCodeVerificationRateLimit, resetUser2FAWithRecoveryCode } from "@lib/server/2fa";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null || context.locals.user === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (!context.locals.user.registered2FA) {
		return new Response("Forbidden", {
			status: 403
		});
	}
	if (!userRecoveryCodeVerificationRateLimit.check(context.locals.user.id, 1)) {
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
	if (!userRecoveryCodeVerificationRateLimit.consume(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const valid = resetUser2FAWithRecoveryCode(context.locals.user.id, code);
	if (!valid) {
		return new Response("Invalid recovery code", {
			status: 400
		});
	}
	userRecoveryCodeVerificationRateLimit.reset(context.locals.user.id);
	return new Response(null, {
		status: 204
	});
}
