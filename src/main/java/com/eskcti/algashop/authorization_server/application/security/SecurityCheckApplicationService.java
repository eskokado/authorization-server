package com.eskcti.algashop.authorization_server.application.security;

import java.util.UUID;

public interface SecurityCheckApplicationService {
	UUID getAuthenticatedUserId();
	boolean isAuthenticated();
	boolean isMachineAuthenticated();
	boolean canAccessOwnProfile();
}
