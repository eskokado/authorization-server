package com.eskcti.algashop.authorization_server.infrastructure.security.password;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationTokenHasherImplTest {

	private final VerificationTokenHasherImpl hasher = new VerificationTokenHasherImpl();

	@Test
	void generate_returnsRandomAlphabeticToken() {
		String first = hasher.generate();
		String second = hasher.generate();

		assertThat(first).hasSize(24).isAlphabetic();
		assertThat(second).hasSize(24).isAlphabetic();
		assertThat(first).isNotEqualTo(second);
	}

	@Test
	void hash_returnsStableBase64UrlSha256() {
		String hash = hasher.hash("plain-token");

		assertThat(hash).isEqualTo(hasher.hash("plain-token"));
		assertThat(hash).matches("[A-Za-z0-9_-]+");
		assertThat(hash).hasSize(43);
	}

	@Test
	void isEqual_comparesPlainTokenAgainstHash() {
		String hash = hasher.hash("plain-token");

		assertThat(hasher.isEqual(hash, "plain-token")).isTrue();
		assertThat(hasher.isEqual(hash, "other-token")).isFalse();
	}
}
