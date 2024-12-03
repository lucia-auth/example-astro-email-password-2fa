import { generateRandomOTP } from "./utils";
import { db } from "./db";
import { Counter, TokenBucketRateLimit } from "./rate-limit";

import type { APIContext } from "astro";

export const sessionEmailVerificationCounter = new Counter<string>(5);
export const userVerificationEmailRateLimit = new TokenBucketRateLimit<number>(5, 60 * 10);

export function createSessionEmailVerificationRequest(
	sessionId: string,
	email: string
): SessionEmailVerificationRequest {
	const code = generateRandomOTP();
	const expiresAt = new Date(Date.now() + 1000 * 60 * 10);
	db.execute(
		`INSERT INTO session_email_verification_request (session_id, expires_at, email, code) VALUES (?, ?, ?, ?)
ON CONFLICT (session_id)
DO UPDATE SET expires_at = ?, email = ?, code = ? WHERE session_id = ?`,
		[
			sessionId,
			Math.floor(expiresAt.getTime() / 1000),
			email,
			code,
			Math.floor(expiresAt.getTime() / 1000),
			email,
			code,
			sessionId
		]
	);

	const request: SessionEmailVerificationRequest = {
		sessionId,
		code,
		email,
		expiresAt
	};
	return request;
}

export function getSessionEmailVerificationRequest(sessionId: string): SessionEmailVerificationRequest | null {
	const row = db.queryOne(
		"SELECT session_id, expires_at, email, code FROM session_email_verification_request WHERE session_id = ?",
		[sessionId]
	);
	if (row === null) {
		return null;
	}
	const request: SessionEmailVerificationRequest = {
		sessionId: row.string(0),
		expiresAt: new Date(row.number(1) * 1000),
		email: row.string(2),
		code: row.string(3)
	};
	if (Date.now() >= request.expiresAt.getTime()) {
		deleteSessionEmailVerificationRequest(request.sessionId);
		return null;
	}
	return request;
}

export function deleteSessionEmailVerificationRequest(sessionId: string): void {
	db.execute("DELETE FROM session_email_verification_request WHERE session_id = ?", [sessionId]);
}

export function deleteUserEmailVerificationRequests(userId: number): void {
	db.execute(
		`DELETE FROM session_email_verification_request WHERE session_id IN (
SELECT id FROM session WHERE user_id = ?
)`,
		[userId]
	);
}

export function sendVerificationEmail(email: string, code: string): void {
	console.log(`To ${email}: Your verification code is ${code}`);
}

export function deleteEmailVerificationRequestCookie(context: APIContext): void {
	context.cookies.set("email_verification", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export interface SessionEmailVerificationRequest {
	sessionId: string;
	expiresAt: Date;
	email: string;
	code: string;
}
