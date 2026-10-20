package com.eskcti.algashop.authorization_server.infrastructure.persistence;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JdbcAuthUserClientScopesQueryServiceTest {

	@Mock
	private JdbcOperations jdbcOperations;

	@InjectMocks
	private JdbcAuthUserClientScopesQueryService queryService;

	@Test
	void findAllowedScopesByRoleAndClientId_returnsScopesReturnedByQuery() {
		when(jdbcOperations.queryForList(anyString(), eq(String.class),
				eq(AuthUserType.MANAGER.name()), eq("algashop-admin-web")))
				.thenReturn(List.of("openid", "users:read"));

		Set<String> scopes = queryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.MANAGER, "algashop-admin-web");

		assertThat(scopes).containsExactlyInAnyOrder("openid", "users:read");
		verify(jdbcOperations).queryForList(anyString(), eq(String.class),
				eq(AuthUserType.MANAGER.name()), eq("algashop-admin-web"));
	}

	@Test
	void findAllowedScopesByRoleAndClientId_returnsEmptySetWhenNothingIsAllowed() {
		when(jdbcOperations.queryForList(anyString(), eq(String.class),
				eq(AuthUserType.CUSTOMER.name()), eq("algashop-admin-web")))
				.thenReturn(List.of());

		Set<String> scopes = queryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.CUSTOMER, "algashop-admin-web");

		assertThat(scopes).isEmpty();
	}

}
