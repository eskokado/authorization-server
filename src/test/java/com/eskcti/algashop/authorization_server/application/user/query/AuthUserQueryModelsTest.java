package com.eskcti.algashop.authorization_server.application.user.query;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AuthUserOutputTest {

	@Test
	void from_mapsAllUserFields() {
		AuthUser user = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");

		AuthUserOutput output = AuthUserOutput.from(user);

		assertThat(output.getId()).isEqualTo(user.getId());
		assertThat(output.getName()).isEqualTo("Alice");
		assertThat(output.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(output.getType()).isEqualTo(AuthUserType.MANAGER);
		assertThat(output.isEnabled()).isTrue();
	}

	@Test
	void builderAndAccessors_roundTrip() {
		UUID id = UUID.randomUUID();
		AuthUserOutput output = AuthUserOutput.builder()
				.id(id)
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.CUSTOMER)
				.enabled(false)
				.build();

		assertThat(output.getId()).isEqualTo(id);
		assertThat(output.getName()).isEqualTo("Alice");
		assertThat(output.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(output.getType()).isEqualTo(AuthUserType.CUSTOMER);
		assertThat(output.isEnabled()).isFalse();

		output.setName("Bob");
		assertThat(output.getName()).isEqualTo("Bob");
	}
}

class PageModelTest {

	@Test
	void of_copiesPageMetadataAndContent() {
		AuthUserOutput first = AuthUserOutput.builder().name("A").build();
		AuthUserOutput second = AuthUserOutput.builder().name("B").build();
		var page = new PageImpl<>(List.of(first, second), PageRequest.of(1, 15), 32L);

		PageModel<AuthUserOutput> model = PageModel.of(page);

		assertThat(model.getNumber()).isEqualTo(1);
		assertThat(model.getSize()).isEqualTo(15);
		assertThat(model.getTotalPages()).isEqualTo(3);
		assertThat(model.getTotalElements()).isEqualTo(32L);
		assertThat(model.getContent()).containsExactly(first, second);
	}

	@Test
	void builder_defaultsToEmptyContent() {
		PageModel<AuthUserOutput> model = PageModel.<AuthUserOutput>builder().build();

		assertThat(model.getContent()).isEmpty();
	}
}

class AuthUserFilterTest {

	@Test
	void defaults_favorFirstPageSortedByNameAscending() {
		AuthUserFilter filter = new AuthUserFilter();

		assertThat(filter.getEmail()).isNull();
		assertThat(filter.getType()).isNull();
		assertThat(filter.getPage()).isZero();
		assertThat(filter.getSize()).isEqualTo(15);
		assertThat(filter.getSort()).isEqualTo("name");
		assertThat(filter.getDirection()).isEqualTo(Sort.Direction.ASC);
	}

	@Test
	void accessors_roundTrip() {
		AuthUserFilter filter = new AuthUserFilter();

		filter.setEmail("alice");
		filter.setType(AuthUserType.OPERATOR);
		filter.setPage(2);
		filter.setSize(50);
		filter.setSort("email");
		filter.setDirection(Sort.Direction.DESC);

		assertThat(filter.getEmail()).isEqualTo("alice");
		assertThat(filter.getType()).isEqualTo(AuthUserType.OPERATOR);
		assertThat(filter.getPage()).isEqualTo(2);
		assertThat(filter.getSize()).isEqualTo(50);
		assertThat(filter.getSort()).isEqualTo("email");
		assertThat(filter.getDirection()).isEqualTo(Sort.Direction.DESC);
	}
}
