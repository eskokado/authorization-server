package com.eskcti.algashop.authorization_server.application.security;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;

import java.util.UUID;

public interface SecurityCheckApplicationService {
	UUID getAuthenticatedUserId();
	boolean isAuthenticated();
	boolean isMachineAuthenticated();
	boolean canAccessOwnProfile();
	boolean canRegisterUserOfType(AuthUserType registrationType);
	boolean canEditUser(AuthUserType editType, UUID editUserId);
	boolean canChangeUserType(AuthUserType currentType, AuthUserType newType);
}
