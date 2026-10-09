package com.eskcti.algashop.authorization_server.infrastructure.security.check;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityAnnotationsTest {

	@Test
	void outerClass_isInstantiable() {
		assertThat(new SecurityAnnotations()).isNotNull();
	}

	@Test
	void canReadUsers_declaresScopeReadPreAuthorize() {
		PreAuthorize preAuthorize = SecurityAnnotations.CanReadUsers.class
				.getAnnotation(PreAuthorize.class);

		assertThat(preAuthorize).isNotNull();
		assertThat(preAuthorize.value()).isEqualTo("hasAuthority('SCOPE_users:read')");
	}

	@Test
	void canWriteUsers_declaresScopeWritePreAuthorize() {
		PreAuthorize preAuthorize = SecurityAnnotations.CanWriteUsers.class
				.getAnnotation(PreAuthorize.class);

		assertThat(preAuthorize).isNotNull();
		assertThat(preAuthorize.value()).isEqualTo("hasAuthority('SCOPE_users:write')");
	}

	@Test
	void canAccessOwnProfile_declaresSecurityCheckExpression() {
		PreAuthorize preAuthorize = SecurityAnnotations.CanAccessOwnProfile.class
				.getAnnotation(PreAuthorize.class);

		assertThat(preAuthorize).isNotNull();
		assertThat(preAuthorize.value()).isEqualTo("@securityCheck.canAccessOwnProfile()");
	}
}
