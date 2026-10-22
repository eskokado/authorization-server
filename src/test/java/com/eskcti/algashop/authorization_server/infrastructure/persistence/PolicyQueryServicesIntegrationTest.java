package com.eskcti.algashop.authorization_server.infrastructure.persistence;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.AuthUserClientScopesQueryService;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.ClientAllowedQueryService;
import com.eskcti.algashop.authorization_server.utils.TestcontainerPostgreSQLConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(TestcontainerPostgreSQLConfig.class)
class PolicyQueryServicesIntegrationTest {

	@Autowired
	private ClientAllowedQueryService clientAllowedQueryService;

	@Autowired
	private AuthUserClientScopesQueryService scopesQueryService;

	@Test
	void findByRole_returnsOnlySeedClientsForEachUserType() {
		assertThat(clientAllowedQueryService.findByRole(AuthUserType.MANAGER))
				.containsExactly("algashop-admin-web");
		assertThat(clientAllowedQueryService.findByRole(AuthUserType.OPERATOR))
				.containsExactly("algashop-admin-web");
		assertThat(clientAllowedQueryService.findByRole(AuthUserType.CUSTOMER))
				.containsExactly("algashop-ecommerce-web");
	}

	@Test
	void findAllowedScopesByRoleAndClientId_returnsSeededScopes() {
		assertThat(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.MANAGER, "algashop-admin-web"))
				.contains("openid", "users:read", "users:write", "products:stock:write");

		assertThat(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.OPERATOR, "algashop-admin-web"))
				.contains("openid", "users:read")
				.doesNotContain("products:stock:write", "users:write");
	}

	@Test
	void findAllowedScopesByRoleAndClientId_returnsEmptySetWhenNoSeedExists() {
		assertThat(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.CUSTOMER, "algashop-admin-web")).isEmpty();
		assertThat(scopesQueryService.findAllowedScopesByRoleAndClientId(
				AuthUserType.MANAGER, "unknown-client")).isEmpty();
	}

}
