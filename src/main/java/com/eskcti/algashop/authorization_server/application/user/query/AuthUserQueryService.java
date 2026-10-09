package com.eskcti.algashop.authorization_server.application.user.query;

import java.util.UUID;

public interface AuthUserQueryService {
	AuthUserOutput findById(UUID userId);
	PageModel<AuthUserOutput> findAll(AuthUserFilter filter);
}

