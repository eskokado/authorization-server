package com.eskcti.algashop.authorization_server.infrastructure.security.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcUserInfoMapperTest {

	private final OidcUserInfoMapper mapper = new OidcUserInfoMapper();

	@Test
	void apply_buildsUserInfoFromIdTokenClaims() {
		OidcUserInfoAuthenticationContext context = mock(OidcUserInfoAuthenticationContext.class);
		OAuth2Authorization authorization = mock(OAuth2Authorization.class);
		OAuth2Authorization.Token<OidcIdToken> idTokenHolder = mock(OAuth2Authorization.Token.class);
		when(context.getAuthorization()).thenReturn(authorization);
		when(authorization.getToken(OidcIdToken.class)).thenReturn(idTokenHolder);
		when(idTokenHolder.getClaims()).thenReturn(Map.of("sub", "alice-id", "name", "Alice"));

		OidcUserInfo userInfo = mapper.apply(context);

		assertThat(userInfo.getSubject()).isEqualTo("alice-id");
		assertThat((String) userInfo.getClaims().get("name")).isEqualTo("Alice");
	}

	@Test
	void apply_fallsBackToJwtSubjectWhenIdTokenIsAbsent() {
		OidcUserInfoAuthenticationContext context = mock(OidcUserInfoAuthenticationContext.class);
		OAuth2Authorization authorization = mock(OAuth2Authorization.class);
		Authentication authentication = mock(Authentication.class);
		Jwt jwt = Jwt.withTokenValue("token")
				.header("alg", "none")
				.subject("alice-id")
				.build();
		when(context.getAuthorization()).thenReturn(authorization);
		when(authorization.getToken(OidcIdToken.class)).thenReturn(null);
		when(context.getAuthentication()).thenReturn(authentication);
		when(authentication.getPrincipal()).thenReturn(new JwtAuthenticationToken(jwt));

		OidcUserInfo userInfo = mapper.apply(context);

		assertThat(userInfo.getClaims()).containsEntry("sub", "alice-id");
	}

	@Test
	void apply_throwsWhenPrincipalIsNotJwtAuthentication() {
		OidcUserInfoAuthenticationContext context = mock(OidcUserInfoAuthenticationContext.class);
		OAuth2Authorization authorization = mock(OAuth2Authorization.class);
		Authentication authentication = mock(Authentication.class);
		when(context.getAuthorization()).thenReturn(authorization);
		when(authorization.getToken(OidcIdToken.class)).thenReturn(null);
		when(context.getAuthentication()).thenReturn(authentication);
		when(authentication.getPrincipal()).thenReturn(null);

		assertThatThrownBy(() -> mapper.apply(context))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void apply_throwsWhenPrincipalTokenIsNull() {
		OidcUserInfoAuthenticationContext context = mock(OidcUserInfoAuthenticationContext.class);
		OAuth2Authorization authorization = mock(OAuth2Authorization.class);
		Authentication authentication = mock(Authentication.class);
		JwtAuthenticationToken principal = mock(JwtAuthenticationToken.class);
		when(context.getAuthorization()).thenReturn(authorization);
		when(authorization.getToken(OidcIdToken.class)).thenReturn(null);
		when(context.getAuthentication()).thenReturn(authentication);
		when(authentication.getPrincipal()).thenReturn(principal);
		when(principal.getToken()).thenReturn(null);

		assertThatThrownBy(() -> mapper.apply(context))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
