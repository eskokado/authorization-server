package com.eskcti.algashop.authorization_server.infrastructure.security.query;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;

import java.util.Set;

public interface AuthUserClientScopesQueryService {
	Set<String> findAllowedScopesByRoleAndClientId(AuthUserType role, String clientId);
}
