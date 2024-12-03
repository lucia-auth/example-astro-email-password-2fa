import { db } from "./db";
import { encodeHexLowerCase } from "@oslojs/encoding";
import { generateRandomOTP } from "./utils";
import { sha256 } from "@oslojs/crypto/sha2";
import { hashPassword } from "./password";
import { BasicRateLimit, TokenBucketRateLimit } from "./rate-limit";

import type { APIContext } from "astro";
import type { User } from "./user";

export const ipPasswordResetRateLimit = new TokenBucketRateLimit<string>(3, 60 * 10);
export const userPasswordResetRateLimit = new TokenBucketRateLimit<number>(3, 60 * 10);
export const userPasswordResetVerificationRateLimit = new BasicRateLimit<number>(5, 60 * 15);

export async function createPasswordResetSession(
	token: string,
	userId: number,
	email: string
): Promise<PasswordResetSessionWithVerificationCode> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const code = generateRandomOTP();
	const codeHash = await hashPassword(code);
	const session: PasswordResetSessionWithVerificationCode = {
		id: sessionId,
		userId,
		email,
		expiresAt: new Date(Date.now() + 1000 * 60 * 10),
		emailVerificationCode: code,
		emailVerified: false,
		twoFactorVerified: false
	};
	db.execute(
		"INSERT INTO password_reset_session (id, user_id, email, email_verification_code_hash, expires_at) VALUES (?, ?, ?, ?, ?)",
		[session.id, session.userId, session.email, codeHash, Math.floor(session.expiresAt.getTime() / 1000)]
	);
	return session;
}

export function validatePasswordResetSessionToken(token: string): PasswordResetSessionValidationResult {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const row = db.queryOne(
		`SELECT password_reset_session.id, password_reset_session.user_id, password_reset_session.email, password_reset_session.expires_at, password_reset_session.email_verified, password_reset_session.two_factor_verified,
user.id, user.email, user.username, IIF(user.totp_key IS NOT NULL, 1, 0)
FROM password_reset_session INNER JOIN user ON user.id = password_reset_session.user_id
WHERE password_reset_session.id = ?`,
		[sessionId]
	);
	if (row === null) {
		return { session: null, user: null };
	}
	const session: PasswordResetSession = {
		id: row.string(0),
		userId: row.number(1),
		email: row.string(2),
		expiresAt: new Date(row.number(3) * 1000),
		emailVerified: Boolean(row.number(4)),
		twoFactorVerified: Boolean(row.number(5))
	};
	const user: User = {
		id: row.number(6),
		email: row.string(7),
		username: row.string(8),
		registered2FA: Boolean(row.number(9))
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM password_reset_session WHERE id = ?", [session.id]);
		return { session: null, user: null };
	}
	return { session, user };
}

export function getPasswordResetSessionEmailVerificationCodeHash(sessionId: string): string | null {
	const row = db.queryOne("SELECT email_verification_code_hash FROM password_reset_session WHERE id = ?", [sessionId]);
	if (row === null) {
		return null;
	}
	const hash = row.string(0);
	return hash;
}

export function setPasswordResetSessionAsEmailVerified(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET email_verified = 1 WHERE id = ?", [sessionId]);
}

export function setPasswordResetSessionAs2FAVerified(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export function invalidateUserPasswordResetSessions(userId: number): void {
	db.execute("DELETE FROM password_reset_session WHERE user_id = ?", [userId]);
}

export function validatePasswordResetSessionRequest(context: APIContext): PasswordResetSessionValidationResult {
	const token = context.cookies.get("password_reset_session")?.value ?? null;
	if (token === null) {
		return { session: null, user: null };
	}
	const result = validatePasswordResetSessionToken(token);
	if (result.session === null) {
		deletePasswordResetSessionTokenCookie(context);
	}
	return result;
}

export function setPasswordResetSessionTokenCookie(context: APIContext, token: string, expiresAt: Date): void {
	context.cookies.set("password_reset_session", token, {
		expires: expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function deletePasswordResetSessionTokenCookie(context: APIContext): void {
	context.cookies.set("password_reset_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function sendPasswordResetEmail(email: string, code: string): void {
	console.log(`To ${email}: Your reset code is ${code}`);
}

export interface PasswordResetSession {
	id: string;
	userId: number;
	email: string;
	expiresAt: Date;
	emailVerified: boolean;
	twoFactorVerified: boolean;
}

export interface PasswordResetSessionWithVerificationCode extends PasswordResetSession {
	emailVerificationCode: string;
}

export type PasswordResetSessionValidationResult =
	| { session: PasswordResetSession; user: User }
	| { session: null; user: null };
