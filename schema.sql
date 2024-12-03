CREATE TABLE user (
    id INTEGER NOT NULL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    totp_key BLOB,
    recovery_code BLOB NOT NULL
);

CREATE INDEX email_index ON user(email);

CREATE TABLE session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES user(id),
    expires_at INTEGER NOT NULL,
    two_factor_verified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE signup_session (
    id TEXT NOT NULL PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verification_code TEXT NOT NULL
);

CREATE TABLE password_reset_session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES user(id),
    expires_at INTEGER NOT NULL,
    email TEXT NOT NULL,
    email_verification_code_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL NOT NULL DEFAULT 0,
    two_factor_verified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE session_email_verification_request (
    session_id TEXT NOT NULL PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    email TEXT NOT NULL,
    code TEXT NOT NULL
);