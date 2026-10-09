package com.eskcti.algashop.authorization_server.domain.model.user;

import com.eskcti.algashop.authorization_server.domain.model.DomainException;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthUserTest {

	@Test
	void brandNew_createsEnabledUserWithGeneratedId() {
		AuthUser user = AuthUser.brandNew(
				"alice@algashop.com",
				"Alice",
				AuthUserType.MANAGER,
				"hash");

		assertThat(user.getId()).isNotNull();
		assertThat(user.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(user.getName()).isEqualTo("Alice");
		assertThat(user.getType()).isEqualTo(AuthUserType.MANAGER);
		assertThat(user.getPassword()).isEqualTo("hash");
		assertThat(user.isEnabled()).isTrue();
	}

	@Test
	void brandNew_rejectsBlankEmail() {
		assertThatThrownBy(() -> AuthUser.brandNew("  ", "Alice", AuthUserType.MANAGER, "hash"))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> AuthUser.brandNew(null, "Alice", AuthUserType.MANAGER, "hash"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void brandNew_generatesDifferentIdsForEachUser() {
		AuthUser first = AuthUser.brandNew("a@x.com", "A", AuthUserType.CUSTOMER, "h1");
		AuthUser second = AuthUser.brandNew("b@x.com", "B", AuthUserType.CUSTOMER, "h2");

		assertThat(first.getId()).isNotEqualTo(second.getId());
	}

	@Test
	void setPassword_acceptsNonBlankValue() {
		AuthUser user = newCustomer();

		user.setPassword("new-hash");

		assertThat(user.getPassword()).isEqualTo("new-hash");
	}

	@Test
	void setPassword_rejectsBlankValue() {
		AuthUser user = newCustomer();

		assertThatThrownBy(() -> user.setPassword("  ")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> user.setPassword(null)).isInstanceOf(IllegalArgumentException.class);
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
		AuthUser user = AuthUser.brandNew("a@x.com", "A", AuthUserType.MANAGER, "hash");

		user.setType(AuthUserType.OPERATOR);

		assertThat(user.getType()).isEqualTo(AuthUserType.OPERATOR);
	}

	@Test
	void setType_rejectsChangeWhenUserIsCustomer() {
		AuthUser user = AuthUser.brandNew("a@x.com", "A", AuthUserType.CUSTOMER, "hash");

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
		AuthUser user = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.OPERATOR, "hash");

		user.anonymize();

		assertThat(user.getName()).isEqualTo("Anonymized User");
		assertThat(user.getEmail()).isEqualTo("anonymized-" + user.getId() + "@deleted.local");
		assertThat(user.isEnabled()).isFalse();
	}

	@Test
	void equals_isBasedOnIdOnly() {
		AuthUser user = AuthUser.brandNew("a@x.com", "A", AuthUserType.CUSTOMER, "hash");
		AuthUser sameId = AuthUser.brandNew("b@x.com", "B", AuthUserType.CUSTOMER, "hash");
		setId(sameId, user.getId());
		AuthUser other = AuthUser.brandNew("c@x.com", "C", AuthUserType.CUSTOMER, "hash");

		assertThat(user).isEqualTo(sameId).hasSameHashCodeAs(sameId);
		assertThat(user).isNotEqualTo(other);
	}

	private AuthUser newCustomer() {
		return AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.CUSTOMER, "hash");
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
