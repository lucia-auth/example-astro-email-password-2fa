import { constantTimeEqual } from "@oslojs/crypto/subtle";
import { encodeBase32UpperCaseNoPadding } from "@oslojs/encoding";

export function generateRandomOTP(): string {
	const bytes = new Uint8Array(5);
	crypto.getRandomValues(bytes);
	const code = encodeBase32UpperCaseNoPadding(bytes);
	return code;
}

export function generateRandomRecoveryCode(): string {
	const recoveryCodeBytes = new Uint8Array(10);
	crypto.getRandomValues(recoveryCodeBytes);
	const recoveryCode = encodeBase32UpperCaseNoPadding(recoveryCodeBytes);
	return recoveryCode;
}

export function constantTimeEqualString(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}
	const aBytes = new TextEncoder().encode(a);
	const bBytes = new TextEncoder().encode(a);
	const equal = constantTimeEqual(aBytes, bBytes);
	return equal;
}
