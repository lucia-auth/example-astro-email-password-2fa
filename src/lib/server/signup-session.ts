import { db } from "./db";
import { encodeHexLowerCase } from "@oslojs/encoding";
import { generateRandomOTP, generateRandomRecoveryCode } from "./utils";
import { sha256 } from "@oslojs/crypto/sha2";
import { hashPassword } from "./password";
import { encryptString } from "./encryption";
import { Counter, TokenBucketRateLimit } from "./rate-limit";

import type { APIContext } from "astro";
import type { User } from "./user";

export const signupSessionEmailVerificationCounter = new Counter<string>(5);
export const ipSendSignUpVerificationEmailRateLimit = new TokenBucketRateLimit<string>(5, 60 * 5);

export async function createSignUpSession(
	token: string,
	email: string,
	username: string,
	password: string
): Promise<SignUpSession> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const emailVerificationCode = generateRandomOTP();
	const passwordHash = await hashPassword(password);
	const session: SignUpSession = {
		id: sessionId,
		expiresAt: new Date(Date.now() + 1000 * 60 * 10),
		email,
		username,
		passwordHash,
		emailVerificationCode
	};
	db.execute(
		"INSERT INTO signup_session (id, expires_at, email, username, password_hash, email_verification_code) VALUES (?, ?, ?, ?, ?, ?)",
		[
			session.id,
			Math.floor(session.expiresAt.getTime() / 1000),
			session.email,
			session.username,
			session.passwordHash,
			session.emailVerificationCode
		]
	);
	return session;
}

export function validateSignUpSessionToken(token: string): SignUpSession | null {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const row = db.queryOne(
		`SELECT id, expires_at, email, username, password_hash, email_verification_code FROM signup_session WHERE id = ?`,
		[sessionId]
	);
	if (row === null) {
		return null;
	}
	const session: SignUpSession = {
		id: row.string(0),
		expiresAt: new Date(row.number(1) * 1000),
		email: row.string(2),
		username: row.string(3),
		passwordHash: row.string(4),
		emailVerificationCode: row.string(5)
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM signup_session WHERE id = ?", [session.id]);
		return null;
	}
	return session;
}

export function invalidateSignUpSession(sessionId: string): void {
	db.execute("DELETE FROM signup_session WHERE id = ?", [sessionId]);
}

export function validateSignUpSessionRequest(context: APIContext): SignUpSession | null {
	const token = context.cookies.get("signup_session")?.value ?? null;
	if (token === null) {
		return null;
	}
	const session = validateSignUpSessionToken(token);
	if (session === null) {
		deleteSignUpSessionTokenCookie(context);
	}
	return session;
}

export function createUserWithSignUpSession(sessionId: string): User {
	const recoveryCode = generateRandomRecoveryCode();
	const encryptedRecoveryCode = encryptString(recoveryCode);
	try {
		db.execute("BEGIN", []);
		let row = db.queryOne(
			"DELETE FROM signup_session WHERE id = ? RETURNING id, expires_at, email, username, password_hash, email_verification_code",
			[sessionId]
		);
		if (row === null) {
			db.execute("COMMIT", []);
			throw new Error("Invalid session");
		}
		const session: SignUpSession = {
			id: row.string(0),
			expiresAt: new Date(row.number(1) * 1000),
			email: row.string(2),
			username: row.string(3),
			passwordHash: row.string(4),
			emailVerificationCode: row.string(5)
		};
		row = db.queryOne(
			"INSERT INTO user (email, username, password_hash, recovery_code) VALUES (?, ?, ?, ?) RETURNING user.id",
			[session.email, session.username, session.passwordHash, encryptedRecoveryCode]
		);
		db.execute("COMMIT", []);
		if (row === null) {
			throw new Error("Unexpected error");
		}
		const user: User = {
			id: row.number(0),
			username: session.username,
			email: session.email,
			registered2FA: false
		};
		return user;
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

export function setSignUpSessionTokenCookie(context: APIContext, token: string, expiresAt: Date): void {
	context.cookies.set("signup_session", token, {
		expires: expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function deleteSignUpSessionTokenCookie(context: APIContext): void {
	context.cookies.set("signup_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function sendSignUpEmail(email: string, code: string): void {
	console.log(`To ${email}: Your reset code is ${code}`);
}

export interface SignUpSession {
	id: string;
	email: string;
	username: string;
	passwordHash: string;
	emailVerificationCode: string;
	expiresAt: Date;
}
