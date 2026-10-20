package com.eskcti.algashop.authorization_server.infrastructure.security.token;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.AuthUserClientScopesQueryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScopePolicyServiceTest {

	@Mock
	private AuthUserClientScopesQueryService scopesQueryService;

	@InjectMocks
	private ScopePolicyService scopePolicyService;

	@Test
	void resolveScopes_returnsEmptySet_whenNoScopeWasAuthorized() {
		Set<String> result = scopePolicyService.resolveScopes(
				AuthUserType.MANAGER, "algashop-admin-web", Set.of());

		assertThat(result).isEmpty();
		verifyNoInteractions(scopesQueryService);
	}

	@Test
	void resolveScopes_returnsAuthorizedScopes_whenRoleHasNoPolicyConfigured() {
		when(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.MANAGER, "algashop-admin-web")).thenReturn(Set.of());

		Set<String> result = scopePolicyService.resolveScopes(
				AuthUserType.MANAGER, "algashop-admin-web", Set.of("openid", "users:read"));

		assertThat(result).containsExactlyInAnyOrder("openid", "users:read");
	}

	@Test
	void resolveScopes_returnsOnlyAllowedScopes_whenRoleHasPolicyConfigured() {
		when(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.OPERATOR, "algashop-admin-web"))
				.thenReturn(Set.of("openid", "users:read"));

		Set<String> result = scopePolicyService.resolveScopes(
				AuthUserType.OPERATOR, "algashop-admin-web",
				Set.of("openid", "users:read", "products:stock:write"));

		assertThat(result).containsExactlyInAnyOrder("openid", "users:read");
	}

	@Test
	void resolveScopes_returnsEmptySet_whenNoAuthorizedScopeIsAllowed() {
		when(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.CUSTOMER, "algashop-admin-web"))
				.thenReturn(Set.of("openid"));

		Set<String> result = scopePolicyService.resolveScopes(
				AuthUserType.CUSTOMER, "algashop-admin-web", Set.of("users:write"));

		assertThat(result).isEmpty();
	}

}
