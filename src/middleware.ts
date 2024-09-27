import { defineMiddleware, sequence } from "astro:middleware";
import { RefillingTokenBucket } from "@lib/server/rate-limit";
import { deleteSessionTokenCookie, setSessionTokenCookie, validateSessionToken } from "@lib/server/session";

const bucket = new RefillingTokenBucket<string>(100, 1);

const rateLimitMiddleware = defineMiddleware((context, next) => {
	// TODO: Assumes X-Forwarded-For is always included.
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP === null) {
		return next();
	}
	let cost: number;
	if (context.request.method === "GET" || context.request.method === "OPTIONS") {
		cost = 1;
	} else {
		cost = 3;
	}
	if (!bucket.consume(clientIP, cost)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	return next();
});

const authMiddleware = defineMiddleware((context, next) => {
	const token = context.cookies.get("session")?.value ?? null;
	if (token === null) {
		context.locals.session = null;
		context.locals.user = null;
		return next();
	}
	const { user, session } = validateSessionToken(token);
	if (session !== null) {
		setSessionTokenCookie(context, token, session.expiresAt);
	} else {
		deleteSessionTokenCookie(context);
	}
	context.locals.session = session;
	context.locals.user = user;
	return next();
});

export const onRequest = sequence(rateLimitMiddleware, authMiddleware);
