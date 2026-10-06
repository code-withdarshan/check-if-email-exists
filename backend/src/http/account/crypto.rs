use data_encoding::{BASE32_NOPAD, HEXLOWER};
use openssl::{
	hash::MessageDigest,
	memcmp, pkcs5,
	rand::rand_bytes,
	sha::sha256,
	symm::{decrypt_aead, encrypt_aead, Cipher},
};
use totp_rs::{Algorithm, TOTP};

const ITERATIONS: usize = 600_000;

pub fn token(bytes: usize) -> anyhow::Result<String> {
	let mut value = vec![0; bytes];
	rand_bytes(&mut value)?;
	Ok(HEXLOWER.encode(&value))
}

pub fn digest(value: &str) -> String {
	HEXLOWER.encode(&sha256(value.as_bytes()))
}
pub fn csrf(token: &str) -> String {
	digest(&format!("reacher-csrf:{token}"))
}
pub fn equal(a: &str, b: &str) -> bool {
	a.len() == b.len() && memcmp::eq(a.as_bytes(), b.as_bytes())
}

pub fn password_hash(password: &str) -> anyhow::Result<String> {
	let salt = token(16)?;
	let mut hash = [0; 32];
	pkcs5::pbkdf2_hmac(
		password.as_bytes(),
		salt.as_bytes(),
		ITERATIONS,
		MessageDigest::sha256(),
		&mut hash,
	)?;
	Ok(format!(
		"pbkdf2-sha256${ITERATIONS}${salt}${}",
		HEXLOWER.encode(&hash)
	))
}

pub fn verify_password(password: &str, stored: &str) -> anyhow::Result<bool> {
	let parts: Vec<_> = stored.split('$').collect();
	anyhow::ensure!(
		parts.len() == 4 && parts[0] == "pbkdf2-sha256" && parts[1] == ITERATIONS.to_string(),
		"Invalid password hash"
	);
	let mut hash = [0; 32];
	pkcs5::pbkdf2_hmac(
		password.as_bytes(),
		parts[2].as_bytes(),
		ITERATIONS,
		MessageDigest::sha256(),
		&mut hash,
	)?;
	Ok(equal(&HEXLOWER.encode(&hash), parts[3]))
}

pub fn encryption_key(value: &str) -> anyhow::Result<Vec<u8>> {
	let key = HEXLOWER.decode(value.as_bytes())?;
	anyhow::ensure!(
		key.len() == 32,
		"Account encryption key must be 32 bytes encoded as 64 lowercase hex characters"
	);
	Ok(key)
}

pub fn encrypt(key: &[u8], user: uuid::Uuid, secret: &[u8]) -> anyhow::Result<Vec<u8>> {
	let mut nonce = [0; 12];
	rand_bytes(&mut nonce)?;
	let mut tag = [0; 16];
	let ciphertext = encrypt_aead(
		Cipher::aes_256_gcm(),
		key,
		Some(&nonce),
		user.as_bytes(),
		secret,
		&mut tag,
	)?;
	Ok([nonce.to_vec(), tag.to_vec(), ciphertext].concat())
}

pub fn decrypt(key: &[u8], user: uuid::Uuid, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
	anyhow::ensure!(blob.len() > 28, "Invalid encrypted authenticator secret");
	Ok(decrypt_aead(
		Cipher::aes_256_gcm(),
		key,
		Some(&blob[..12]),
		user.as_bytes(),
		&blob[28..],
		&blob[12..28],
	)?)
}

pub fn authenticator(secret: Vec<u8>, username: &str) -> anyhow::Result<TOTP> {
	Ok(TOTP::new(
		Algorithm::SHA1,
		6,
		1,
		30,
		secret,
		Some("Email Checker".into()),
		username.into(),
	)?)
}

pub fn new_secret() -> anyhow::Result<Vec<u8>> {
	let mut secret = vec![0; 20];
	rand_bytes(&mut secret)?;
	Ok(secret)
}
pub fn setup_key(secret: &[u8]) -> String {
	BASE32_NOPAD.encode(secret)
}

/// Return the matching step, so the caller can atomically prevent replay.
pub fn matching_step(totp: &TOTP, code: &str, seconds: u64, last: i64) -> Option<i64> {
	if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
		return None;
	}
	let current = (seconds / 30) as i64;
	(current - 1..=current + 1)
		.filter(|step| *step >= 0 && *step > last)
		.find(|step| equal(&totp.generate(*step as u64 * 30), code))
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn password_hashes_are_salted_and_verify() {
		let a = password_hash("a long test password").unwrap();
		let b = password_hash("a long test password").unwrap();
		assert_ne!(a, b);
		assert!(verify_password("a long test password", &a).unwrap());
		assert!(!verify_password("wrong", &a).unwrap());
	}
	#[test]
	fn totp_rfc_vector_replay_and_window() {
		let totp = authenticator(b"12345678901234567890".to_vec(), "test").unwrap();
		assert_eq!(totp.generate(59), "287082");
		assert_eq!(matching_step(&totp, "287082", 59, -1), Some(1));
		assert_eq!(matching_step(&totp, "287082", 59, 1), None);
		assert_eq!(matching_step(&totp, "287082", 120, -1), None);
		assert_eq!(matching_step(&totp, "bad123", 59, -1), None);
	}
	#[test]
	fn encryption_is_bound_to_user_and_detects_tampering() {
		let key = [7; 32];
		let user = uuid::Uuid::new_v4();
		let mut blob = encrypt(&key, user, b"test secret").unwrap();
		assert_eq!(decrypt(&key, user, &blob).unwrap(), b"test secret");
		assert!(decrypt(&key, uuid::Uuid::new_v4(), &blob).is_err());
		blob[28] ^= 1;
		assert!(decrypt(&key, user, &blob).is_err());
	}
}
