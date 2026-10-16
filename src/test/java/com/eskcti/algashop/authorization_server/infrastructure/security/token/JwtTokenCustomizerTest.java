package com.eskcti.algashop.authorization_server.infrastructure.security.token;

import com.eskcti.algashop.authorization_server.infrastructure.security.oidc.OidcUserInfoService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenCustomizerTest {

	@Mock
	private OidcUserInfoService oidcUserInfoService;

	@InjectMocks
	private JwtTokenCustomizer customizer;

	private static final OAuth2TokenType ID_TOKEN = new OAuth2TokenType("id_token");

	private JwtEncodingContext context(OAuth2TokenType tokenType,
			AuthorizationGrantType grantType, String email) {
		Authentication principal = new UsernamePasswordAuthenticationToken(email, "N/A");
		return JwtEncodingContext.with(
						JwsHeader.with(MacAlgorithm.HS256),
						JwtClaimsSet.builder())
				.tokenType(tokenType)
				.authorizationGrantType(grantType)
				.principal(principal)
				.build();
	}

	private OidcUserInfo userInfo(String subject, String type) {
		return OidcUserInfo.builder()
				.subject(subject)
				.claim("type", type)
				.build();
	}

	@Test
	void customize_setsSubjectAndRoleClaim_forAccessTokenWithAuthCodeFlow() {
		JwtEncodingContext context = context(OAuth2TokenType.ACCESS_TOKEN,
				AuthorizationGrantType.AUTHORIZATION_CODE, "user@example.com");
		when(oidcUserInfoService.loadUser("user@example.com"))
				.thenReturn(userInfo("user-1", "CUSTOMER"));

		customizer.customize(context);

		JwtClaimsSet claims = context.getClaims().build();
		assertThat(claims.getSubject()).isEqualTo("user-1");
		assertThat(claims.getClaimAsString("role")).isEqualTo("CUSTOMER");
	}

	@Test
	void customize_setsSubjectAndRoleClaim_forAccessTokenWithRefreshTokenFlow() {
		JwtEncodingContext context = context(OAuth2TokenType.ACCESS_TOKEN,
				AuthorizationGrantType.REFRESH_TOKEN, "user@example.com");
		when(oidcUserInfoService.loadUser("user@example.com"))
				.thenReturn(userInfo("user-1", "MANAGER"));

		customizer.customize(context);

		JwtClaimsSet claims = context.getClaims().build();
		assertThat(claims.getSubject()).isEqualTo("user-1");
		assertThat(claims.getClaimAsString("role")).isEqualTo("MANAGER");
	}

	@Test
	void customize_putsAllUserClaims_forIdToken() {
		JwtEncodingContext context = context(ID_TOKEN,
				AuthorizationGrantType.AUTHORIZATION_CODE, "user@example.com");
		when(oidcUserInfoService.loadUser("user@example.com"))
				.thenReturn(userInfo("user-1", "CUSTOMER"));

		customizer.customize(context);

		JwtClaimsSet claims = context.getClaims().build();
		assertThat(claims.getSubject()).isEqualTo("user-1");
		assertThat(claims.getClaimAsString("type")).isEqualTo("CUSTOMER");
	}

	@Test
	void customize_doesNotLoadUser_forAccessTokenWithClientCredentialsFlow() {
		JwtEncodingContext context = context(OAuth2TokenType.ACCESS_TOKEN,
				AuthorizationGrantType.CLIENT_CREDENTIALS, "service@example.com");
		context.getClaims().claim("existing", "value");

		customizer.customize(context);

		verifyNoInteractions(oidcUserInfoService);
		assertThat(context.getClaims().build().getClaims()).containsOnlyKeys("existing");
	}

	@Test
	void customize_doesNotLoadUser_forRefreshTokenType() {
		JwtEncodingContext context = context(OAuth2TokenType.REFRESH_TOKEN,
				AuthorizationGrantType.AUTHORIZATION_CODE, "user@example.com");
		context.getClaims().claim("existing", "value");

		customizer.customize(context);

		verifyNoInteractions(oidcUserInfoService);
		assertThat(context.getClaims().build().getClaims()).containsOnlyKeys("existing");
	}
}
