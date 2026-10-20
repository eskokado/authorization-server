package com.eskcti.algashop.authorization_server.infrastructure.security.code;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class DelegatingAuthorizationCodeRequestValidatorTest {

	private static final String AUTHORIZATION_URI = "http://auth.algashop.local:8081/oauth2/authorize";
	private static final String CLIENT_ID = "algashop-admin-web";
	private static final String REDIRECT_URI = "http://admin.algashop.local:4200";

	@Mock
	private AuthUserClientAccessPolicyValidator clientAccessPolicyValidator;

	@InjectMocks
	private DelegatingAuthorizationCodeRequestValidator validator;

	@Test
	void accept_delegatesToPolicyValidator_whenDefaultValidatorsPass() {
		var context = context(REDIRECT_URI, Set.of("openid", "users:read"));

		validator.accept(context);

		verify(clientAccessPolicyValidator).accept(context);
	}

	@Test
	void accept_failsOnRedirectUri_beforePolicyValidator() {
		var context = context("http://evil.example.com", Set.of("openid"));

		assertThatThrownBy(() -> validator.accept(context))
				.isInstanceOfSatisfying(OAuth2AuthorizationCodeRequestAuthenticationException.class,
						exception -> assertThat(exception.getError().getErrorCode())
								.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));

		verifyNoInteractions(clientAccessPolicyValidator);
	}

	@Test
	void accept_failsOnScope_beforePolicyValidator() {
		var context = context(REDIRECT_URI, Set.of("openid", "admin:everything"));

		assertThatThrownBy(() -> validator.accept(context))
				.isInstanceOfSatisfying(OAuth2AuthorizationCodeRequestAuthenticationException.class,
						exception -> assertThat(exception.getError().getErrorCode())
								.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));

		verifyNoInteractions(clientAccessPolicyValidator);
	}

	private OAuth2AuthorizationCodeRequestAuthenticationContext context(
			String redirectUri, Set<String> scopes) {
		Authentication principal = UsernamePasswordAuthenticationToken.authenticated(
				"alice@algashop.com", "N/A", List.of());
		var token = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, CLIENT_ID, principal, redirectUri, "state", scopes, Map.of());
		return OAuth2AuthorizationCodeRequestAuthenticationContext.with(token)
				.registeredClient(registeredClient())
				.build();
	}

	private RegisteredClient registeredClient() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(CLIENT_ID)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope("openid")
				.scope("users:read")
				.build();
	}

}
