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
class JdbcClientAllowedQueryServiceTest {

	@Mock
	private JdbcOperations jdbcOperations;

	@InjectMocks
	private JdbcClientAllowedQueryService queryService;

	@Test
	void findByRole_returnsClientsReturnedByQuery() {
		when(jdbcOperations.queryForList(anyString(), eq(String.class),
				eq(AuthUserType.MANAGER.name())))
				.thenReturn(List.of("algashop-admin-web"));

		Set<String> clients = queryService.findByRole(AuthUserType.MANAGER);

		assertThat(clients).containsExactly("algashop-admin-web");
		verify(jdbcOperations).queryForList(anyString(), eq(String.class),
				eq(AuthUserType.MANAGER.name()));
	}

	@Test
	void findByRole_returnsEmptySetWhenRoleHasNoAllowedClient() {
		when(jdbcOperations.queryForList(anyString(), eq(String.class),
				eq(AuthUserType.OPERATOR.name())))
				.thenReturn(List.of());

		Set<String> clients = queryService.findByRole(AuthUserType.OPERATOR);

		assertThat(clients).isEmpty();
	}

}
