package com.eskcti.algashop.authorization_server.infrastructure.security.check;

import com.eskcti.algashop.authorization_server.application.security.SecurityCheckApplicationService;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service("securityCheck")
@Slf4j
public class OAuth2SecurityCheckApplicationServiceImpl
		implements SecurityCheckApplicationService {

	private static final String SCOPE_USERS_WRITE = "SCOPE_users:write";
	private static final String ROLE_MANAGER = "ROLE_" + AuthUserType.MANAGER.name();

	@Override
	public UUID getAuthenticatedUserId() {
		if (isMachineAuthenticated()) {
			throw new AccessDeniedException("Machine users do not have user ID");
		}
		Jwt jwt = getJwt();

		try {
			return UUID.fromString(jwt.getSubject());
		} catch (IllegalArgumentException e) {
			log.error("Invalid user ID in JWT subject: {}", jwt.getSubject(), e);
			throw new AccessDeniedException("Invalid user ID in JWT subject");
		}
	}

	@Override
	public boolean isAuthenticated() {
		try {
			return getAuthentication().isAuthenticated();
		} catch (IllegalStateException e) {
			log.debug(e.getMessage(), e);
			return false;
		}
	}

	@Override
	public boolean isMachineAuthenticated() {
		Jwt jwt;
		try {
			jwt = getJwt();
		} catch (IllegalStateException e) {
			log.debug(e.getMessage(), e);
			return false;
		}
		List<String> audience = jwt.getAudience();
		return audience != null && audience.contains(jwt.getSubject());
	}

	@Override
	public boolean canAccessOwnProfile() {
		return this.isAuthenticated() && !isMachineAuthenticated();
	}

	@Override
	public boolean canRegisterUserOfType(AuthUserType registrationType) {
		if (!isAuthenticated()) {
			return false;
		}

		if (!hasAuthority(SCOPE_USERS_WRITE)) {
			return false;
		}

		if (registrationType == AuthUserType.CUSTOMER) {
			return isMachineAuthenticated();
		}

		if (hasAuthority(ROLE_MANAGER)) {
			return registrationType == AuthUserType.MANAGER
					|| registrationType == AuthUserType.OPERATOR;
		}

		return false;
	}

	private boolean hasAuthority(String rawAuthority) {
		Authentication authentication;
		try {
			authentication = getAuthentication();
		} catch (IllegalStateException e) {
			log.debug(e.getMessage(), e);
			return false;
		}

		return authentication.getAuthorities()
				.stream().anyMatch(a -> Objects.equals(a.getAuthority(), rawAuthority));
	}

	private Jwt getJwt() {
		Authentication authentication = getAuthentication();
		if (authentication.getPrincipal() instanceof Jwt jwt) {
			return jwt;
		}
		throw new IllegalStateException("Authentication principal is not a JWT");
	}

	private Authentication getAuthentication() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new IllegalStateException("No authentication found");
		}
		return authentication;
	}
}
