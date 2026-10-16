package com.eskcti.algashop.authorization_server.infrastructure.security.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtGrantedAuthoritiesDelegatingConverterTest {

	private final JwtGrantedAuthoritiesDelegatingConverter converter =
			new JwtGrantedAuthoritiesDelegatingConverter();

	private Jwt jwtWith(String scope, String role) {
		var builder = Jwt.withTokenValue("token")
				.header("alg", "none")
				.subject("subject");
		if (scope != null) {
			builder.claim("scope", scope);
		}
		if (role != null) {
			builder.claim("role", role);
		}
		return builder.build();
	}

	@Test
	void convert_addsRoleAuthority_whenRoleClaimIsPresent() {
		Collection<GrantedAuthority> authorities =
				converter.convert(jwtWith("users:read", "CUSTOMER"));

		assertThat(authorities)
				.extracting(GrantedAuthority::getAuthority)
				.contains("ROLE_CUSTOMER", "SCOPE_users:read");
	}

	@Test
	void convert_returnsOnlyScopeAuthorities_whenRoleClaimIsBlank() {
		Collection<GrantedAuthority> authorities =
				converter.convert(jwtWith("users:read", " "));

		assertThat(authorities)
				.extracting(GrantedAuthority::getAuthority)
				.containsExactly("SCOPE_users:read");
	}

	@Test
	void convert_returnsEmptyAuthorities_whenNeitherScopeNorRoleClaimsArePresent() {
		Collection<GrantedAuthority> authorities = converter.convert(jwtWith(null, null));

		assertThat(authorities).isEmpty();
	}

	@Test
	void convert_handlesMultipleScopes() {
		Collection<GrantedAuthority> authorities =
				converter.convert(jwtWith("users:read users:write", "MANAGER"));

		assertThat(authorities)
				.extracting(GrantedAuthority::getAuthority)
				.contains("SCOPE_users:read", "SCOPE_users:write", "ROLE_MANAGER");
	}
}
