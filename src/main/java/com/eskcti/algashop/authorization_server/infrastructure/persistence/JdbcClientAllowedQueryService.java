package com.eskcti.algashop.authorization_server.infrastructure.persistence;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.ClientAllowedQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JdbcClientAllowedQueryService implements ClientAllowedQueryService {

	private static final String SQL = """
			SELECT client_id
			FROM auth_user_type_client_allowed
			WHERE auth_user_type = ?
			""";

	private final JdbcOperations jdbcOperations;

	@Override
	public Set<String> findByRole(AuthUserType role) {
		return new HashSet<>(jdbcOperations.queryForList(SQL, String.class, role.name()));
	}
}
