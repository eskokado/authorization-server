package com.eskcti.algashop.authorization_server.infrastructure.security.query;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;

import java.util.Set;

public interface ClientAllowedQueryService {
	Set<String> findByRole(AuthUserType role);
}
