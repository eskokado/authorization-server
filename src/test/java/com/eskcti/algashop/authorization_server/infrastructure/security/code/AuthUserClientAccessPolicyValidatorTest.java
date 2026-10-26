package com.eskcti.algashop.authorization_server.infrastructure.security.code;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.ClientAllowedQueryService;
import com.eskcti.algashop.authorization_server.infrastructure.security.token.ScopePolicyService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.newUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthUserClientAccessPolicyValidatorTest {

	private static final String AUTHORIZATION_URI = "http://auth.algashop.local:8081/oauth2/authorize";
	private static final String CLIENT_ID = "algashop-admin-web";
	private static final String REDIRECT_URI = "http://admin.algashop.local:4200";
	private static final String EMAIL = "alice@algashop.com";

	@Mock
	private AuthUserRepository authUserRepository;

	@Mock
	private ClientAllowedQueryService clientAllowedQueryService;

	@Mock
	private ScopePolicyService scopePolicyService;

	@InjectMocks
	private AuthUserClientAccessPolicyValidator validator;

	@Test
	void accept_skipsValidation_whenPrincipalIsNull() {
		OAuth2AuthorizationCodeRequestAuthenticationToken token =
				mock(OAuth2AuthorizationCodeRequestAuthenticationToken.class);
		when(token.getPrincipal()).thenReturn(null);
		OAuth2AuthorizationCodeRequestAuthenticationContext context =
				mock(OAuth2AuthorizationCodeRequestAuthenticationContext.class);
		when(context.getAuthentication()).thenReturn(token);

		validator.accept(context);

		verifyNoInteractions(authUserRepository, clientAllowedQueryService, scopePolicyService);
	}

	@Test
	void accept_skipsValidation_whenPrincipalIsNotAuthenticated() {
		Authentication principal = UsernamePasswordAuthenticationToken.unauthenticated(EMAIL, "N/A");

		validator.accept(context(token(principal)));

		verifyNoInteractions(authUserRepository, clientAllowedQueryService, scopePolicyService);
	}

	@Test
	void accept_skipsValidation_whenPrincipalIsAnonymous() {
		Authentication principal = new AnonymousAuthenticationToken("key", EMAIL,
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

		validator.accept(context(token(principal)));

		verifyNoInteractions(authUserRepository, clientAllowedQueryService, scopePolicyService);
	}

	@Test
	void accept_throwsWhenAuthenticatedUserDoesNotExist() {
		when(authUserRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> validator.accept(context(token(authenticatedPrincipal()))))
				.isInstanceOf(UsernameNotFoundException.class)
				.hasMessageContaining(EMAIL);
	}

	@Test
	void accept_throwsAccessDenied_whenUserTypeCannotUseClient() {
		Authentication principal = authenticatedPrincipal();
		when(authUserRepository.findByEmail(EMAIL))
				.thenReturn(Optional.of(user(AuthUserType.CUSTOMER)));
		when(clientAllowedQueryService.findByRole(AuthUserType.CUSTOMER))
				.thenReturn(Set.of("algashop-ecommerce-web"));

		assertThatThrownBy(() -> validator.accept(context(token(principal))))
				.isInstanceOfSatisfying(OAuth2AuthorizationCodeRequestAuthenticationException.class, exception -> {
					assertThat(exception.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED);
					assertThat(exception.getAuthorizationCodeRequestAuthentication()).isNotNull();
					assertThat(exception.getAuthorizationCodeRequestAuthentication().isAuthenticated()).isTrue();
					assertThat(exception.getAuthorizationCodeRequestAuthentication().getPrincipal())
							.isSameAs(principal);
				});

		verifyNoInteractions(scopePolicyService);
	}

	@Test
	void accept_throwsInvalidScope_whenUserTypeIsNotAllowedToUseRequestedScopes() {
		when(authUserRepository.findByEmail(EMAIL))
				.thenReturn(Optional.of(user(AuthUserType.OPERATOR)));
		when(clientAllowedQueryService.findByRole(AuthUserType.OPERATOR))
				.thenReturn(Set.of(CLIENT_ID));
		when(scopePolicyService.resolveScopes(AuthUserType.OPERATOR, CLIENT_ID,
				Set.of("openid", "users:read")))
				.thenReturn(Set.of("openid"));

		assertThatThrownBy(() -> validator.accept(context(token(authenticatedPrincipal()))))
				.isInstanceOfSatisfying(OAuth2AuthorizationCodeRequestAuthenticationException.class, exception -> {
					assertThat(exception.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
					assertThat(exception.getError().getDescription()).contains("users:read");
					assertThat(exception.getAuthorizationCodeRequestAuthentication()).isNotNull();
				});
	}

	@Test
	void accept_allowsRequest_whenUserTypeCanUseClientAndScopes() {
		when(authUserRepository.findByEmail(EMAIL))
				.thenReturn(Optional.of(user(AuthUserType.MANAGER)));
		when(clientAllowedQueryService.findByRole(AuthUserType.MANAGER))
				.thenReturn(Set.of(CLIENT_ID));
		when(scopePolicyService.resolveScopes(AuthUserType.MANAGER, CLIENT_ID,
				Set.of("openid", "users:read")))
				.thenReturn(Set.of("openid", "users:read"));

		validator.accept(context(token(authenticatedPrincipal())));
	}

	private OAuth2AuthorizationCodeRequestAuthenticationToken token(Authentication principal) {
		return new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, CLIENT_ID, principal, REDIRECT_URI, "state",
				Set.of("openid", "users:read"), Map.of());
	}

	private OAuth2AuthorizationCodeRequestAuthenticationContext context(
			OAuth2AuthorizationCodeRequestAuthenticationToken token) {
		return OAuth2AuthorizationCodeRequestAuthenticationContext.with(token)
				.registeredClient(RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId(CLIENT_ID)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.redirectUri(REDIRECT_URI)
						.scope("openid")
						.scope("users:read")
						.build())
				.build();
	}

	private Authentication authenticatedPrincipal() {
		return UsernamePasswordAuthenticationToken.authenticated(EMAIL, "N/A", List.of());
	}

	private AuthUser user(AuthUserType type) {
		return newUser(EMAIL, "Alice", type);
	}

}
