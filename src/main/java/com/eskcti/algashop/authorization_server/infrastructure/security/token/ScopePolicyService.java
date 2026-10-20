package com.eskcti.algashop.authorization_server.infrastructure.security.token;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.AuthUserClientScopesQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ScopePolicyService {

	private final AuthUserClientScopesQueryService scopesQueryService;

	public Set<String> resolveScopes(AuthUserType role, String clientId, Set<String> authorizedScopes) {
		if (authorizedScopes.isEmpty()) {
			return new HashSet<>();
		}

		Set<String> allowedScopes = scopesQueryService.findAllowedScopesByRoleAndClientId(role, clientId);

		if (allowedScopes.isEmpty()) {
			return new HashSet<>(authorizedScopes);
		}

		return authorizedScopes.stream()
				.filter(allowedScopes::contains)
				.collect(Collectors.toSet());
	}

}
