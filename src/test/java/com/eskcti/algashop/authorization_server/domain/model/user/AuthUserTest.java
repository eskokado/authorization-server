package com.eskcti.algashop.authorization_server.domain.model.user;

import com.eskcti.algashop.authorization_server.domain.model.DomainException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.UUID;

import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.ENCRYPTED_PASSWORD;
import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.newUser;
import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.verified;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthUserTest {

	@Test
	void brandNew_createsEnabledUserWithGeneratedId() {
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);

		assertThat(user.getId()).isNotNull();
		assertThat(user.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(user.getName()).isEqualTo("Alice");
		assertThat(user.getType()).isEqualTo(AuthUserType.MANAGER);
		assertThat(user.getPassword()).isEqualTo(ENCRYPTED_PASSWORD);
		assertThat(user.isEnabled()).isTrue();
		assertThat(user.isEmailVerified()).isFalse();
	}

	@Test
	void brandNew_rejectsBlankEmail() {
		assertThatThrownBy(() -> newUser("  ", "Alice", AuthUserType.MANAGER))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> newUser(null, "Alice", AuthUserType.MANAGER))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void brandNew_generatesDifferentIdsForEachUser() {
		AuthUser first = newUser("a@x.com", "A", AuthUserType.CUSTOMER);
		AuthUser second = newUser("b@x.com", "B", AuthUserType.CUSTOMER);

		assertThat(first.getId()).isNotEqualTo(second.getId());
	}

	@Test
	void generateVerificationToken_returnsPlainTokenAndStoresHashWithExpiration() {
		AuthUser user = newCustomer();
		Duration expiresIn = Duration.ofHours(24);
		VerificationTokenHasher hasher = new VerificationTokenHasher() {
			@Override
			public String generate() {
				return "plain-token";
			}

			@Override
			public String hash(String plainToken) {
				return "hashed-" + plainToken;
			}

			@Override
			public boolean isEqual(String hashed, String plainToken) {
				return hashed.equals(hash(plainToken));
			}
		};

		OffsetDateTime before = OffsetDateTime.now();
		String plainToken = user.generateVerificationToken(expiresIn, hasher);
		OffsetDateTime after = OffsetDateTime.now();

		assertThat(plainToken).isEqualTo("plain-token");
		assertThat(user.getVerificationToken()).isEqualTo("hashed-plain-token");
		assertThat(user.getVerificationTokenExpirationDate())
				.isBetween(before.plus(expiresIn), after.plus(expiresIn));
	}

	@Test
	void isDisabled_returnsTrueWhenEmailIsNotVerified() {
		AuthUser user = newCustomer();

		assertThat(user.isEnabled()).isTrue();
		assertThat(user.isDisabled()).isTrue();
	}

	@Test
	void isDisabled_returnsTrueWhenUserIsDisabled() {
		AuthUser user = verified(newCustomer());
		user.setEnabled(false);

		assertThat(user.isDisabled()).isTrue();
	}

	@Test
	void isDisabled_returnsFalseWhenEmailIsVerifiedAndUserIsEnabled() {
		AuthUser user = verified(newCustomer());

		assertThat(user.isDisabled()).isFalse();
	}

	@Test
	void setName_acceptsNonBlankValue() {
		AuthUser user = newCustomer();

		user.setName("Updated Name");

		assertThat(user.getName()).isEqualTo("Updated Name");
	}

	@Test
	void setName_rejectsBlankValue() {
		AuthUser user = newCustomer();

		assertThatThrownBy(() -> user.setName("")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> user.setName(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void setEnabled_togglesActivation() {
		AuthUser user = newCustomer();

		user.setEnabled(false);

		assertThat(user.isEnabled()).isFalse();
	}

	@Test
	void setType_allowsChangeForNonCustomerUser() {
		AuthUser user = newUser("a@x.com", "A", AuthUserType.MANAGER);

		user.setType(AuthUserType.OPERATOR);

		assertThat(user.getType()).isEqualTo(AuthUserType.OPERATOR);
	}

	@Test
	void setType_rejectsChangeWhenUserIsCustomer() {
		AuthUser user = newUser("a@x.com", "A", AuthUserType.CUSTOMER);

		assertThatThrownBy(() -> user.setType(AuthUserType.MANAGER))
				.isInstanceOf(DomainException.class)
				.hasMessageContaining("CUSTOMER");
	}

	@Test
	void setType_rejectsNullType() {
		AuthUser user = newCustomer();

		assertThatThrownBy(() -> user.setType(null)).isInstanceOf(NullPointerException.class);
	}

	@Test
	void anonymize_scrubbesPersonalDataAndDisablesUser() {
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.OPERATOR);

		user.anonymize();

		assertThat(user.getName()).isEqualTo("Anonymized User");
		assertThat(user.getEmail()).isEqualTo("anonymized-" + user.getId() + "@deleted.local");
		assertThat(user.isEnabled()).isFalse();
	}

	@Test
	void equals_isBasedOnIdOnly() {
		AuthUser user = newUser("a@x.com", "A", AuthUserType.CUSTOMER);
		AuthUser sameId = newUser("b@x.com", "B", AuthUserType.CUSTOMER);
		setId(sameId, user.getId());
		AuthUser other = newUser("c@x.com", "C", AuthUserType.CUSTOMER);

		assertThat(user).isEqualTo(sameId).hasSameHashCodeAs(sameId);
		assertThat(user).isNotEqualTo(other);
	}

	private AuthUser newCustomer() {
		return newUser("alice@algashop.com", "Alice", AuthUserType.CUSTOMER);
	}

	private void setId(AuthUser user, UUID id) {
		try {
			var field = AuthUser.class.getDeclaredField("id");
			field.setAccessible(true);
			field.set(user, id);
		} catch (ReflectiveOperationException e) {
			throw new IllegalStateException(e);
		}
	}
}
