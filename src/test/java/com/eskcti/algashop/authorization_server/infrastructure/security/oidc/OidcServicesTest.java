package com.eskcti.algashop.authorization_server.infrastructure.security.oidc;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.infrastructure.security.query.OAuth2AuthorizationQueryService;
import com.eskcti.algashop.authorization_server.infrastructure.security.userinfo.AuthUserDetailService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OidcUserInfoServiceTest {

	@Mock
	private AuthUserRepository authUserRepository;

	@InjectMocks
	private OidcUserInfoService service;

	@Test
	void loadUser_buildsUserInfoFromAggregate() {
		AuthUser user = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");
		setCreatedAt(user, OffsetDateTime.parse("2026-01-01T10:00:00Z"));
		when(authUserRepository.findByEmail("alice@algashop.com")).thenReturn(Optional.of(user));

		OidcUserInfo userInfo = service.loadUser("alice@algashop.com");

		assertThat(userInfo.getSubject()).isEqualTo(user.getId().toString());
		assertThat((String) userInfo.getClaims().get("name")).isEqualTo("Alice");
		assertThat(userInfo.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(userInfo.getClaims()).containsEntry("type", "MANAGER");
		assertThat(userInfo.getClaims()).containsEntry("created_at", "1767261600");
	}

	@Test
	void loadUser_throwsWhenUserDoesNotExist() {
		when(authUserRepository.findByEmail("ghost@algashop.com")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.loadUser("ghost@algashop.com"))
				.isInstanceOf(UsernameNotFoundException.class)
				.hasMessageContaining("ghost@algashop.com");
	}

	private void setCreatedAt(AuthUser user, OffsetDateTime createdAt) {
		try {
			var field = com.eskcti.algashop.authorization_server.domain.model.AbstractAuditableAggregateRoot.class
					.getDeclaredField("createdAt");
			field.setAccessible(true);
			field.set(user, createdAt);
		} catch (ReflectiveOperationException e) {
			throw new IllegalStateException(e);
		}
	}
}

@ExtendWith(MockitoExtension.class)
class AuthUserDetailServiceTest {

	@Mock
	private AuthUserRepository authUserRepository;

	@InjectMocks
	private AuthUserDetailService service;

	@Test
	void loadUserByUsername_returnsEnabledUserDetails() {
		AuthUser user = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");
		when(authUserRepository.findByEmail("alice@algashop.com")).thenReturn(Optional.of(user));

		var details = service.loadUserByUsername("alice@algashop.com");

		assertThat(details.getUsername()).isEqualTo("alice@algashop.com");
		assertThat(details.getPassword()).isEqualTo("hash");
		assertThat(details.isEnabled()).isTrue();
	}

	@Test
	void loadUserByUsername_marksDisabledUser() {
		AuthUser user = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");
		user.setEnabled(false);
		when(authUserRepository.findByEmail("alice@algashop.com")).thenReturn(Optional.of(user));

		var details = service.loadUserByUsername("alice@algashop.com");

		assertThat(details.isEnabled()).isFalse();
	}

	@Test
	void loadUserByUsername_throwsWhenUserDoesNotExist() {
		when(authUserRepository.findByEmail("ghost@algashop.com")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.loadUserByUsername("ghost@algashop.com"))
				.isInstanceOf(UsernameNotFoundException.class);
	}
}

@ExtendWith(MockitoExtension.class)
class OdicRevokeAuthorizationsLogoutHandlerTest {

	@Mock
	private OAuth2AuthorizationQueryService authorizationQueryService;

	@Mock
	private OAuth2AuthorizationService authorizationService;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	@InjectMocks
	private OdicRevokeAuthorizationsLogoutHandler handler;

	@Test
	void logout_ignoresNullAuthentication() {
		handler.logout(request, response, null);

		verify(authorizationQueryService, never()).findAuthorizationIds(anyString());
		verify(authorizationService, never()).remove(any());
	}

	@Test
	void logout_ignoresAuthenticationWithoutName() {
		AuthenticationWithoutName authentication = new AuthenticationWithoutName();

		handler.logout(request, response, authentication);

		verify(authorizationQueryService, never()).findAuthorizationIds(anyString());
	}

	@Test
	void logout_revokesKnownAuthorizations() {
		OidcLogoutAuthenticationToken authentication = mock(OidcLogoutAuthenticationToken.class);
		when(authentication.getName()).thenReturn("alice@algashop.com");
		var principal = new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());
		when(authentication.isPrincipalAuthenticated()).thenReturn(true);
		when(authentication.getPrincipal()).thenReturn(principal);
		when(authorizationQueryService.findAuthorizationIds("alice@algashop.com"))
				.thenReturn(List.of("auth-1", "auth-2"));
		OAuth2Authorization authorization = mock(OAuth2Authorization.class);
		when(authorizationService.findById("auth-1")).thenReturn(authorization);
		when(authorizationService.findById("auth-2")).thenReturn(null);

		handler.logout(request, response, authentication);

		verify(authorizationService).remove(authorization);
		verify(authorizationService).findById("auth-2");
	}

	@Test
	void logout_skipsSecurityContextClearWhenPrincipalNotAuthenticated() {
		OidcLogoutAuthenticationToken authentication = mock(OidcLogoutAuthenticationToken.class);
		when(authentication.getName()).thenReturn("alice@algashop.com");
		when(authentication.isPrincipalAuthenticated()).thenReturn(false);
		when(authorizationQueryService.findAuthorizationIds("alice@algashop.com")).thenReturn(List.of());

		handler.logout(request, response, authentication);

		verify(authorizationService, never()).remove(any());
	}

	private static final class AuthenticationWithoutName
			extends UsernamePasswordAuthenticationToken {
		private AuthenticationWithoutName() {
			super("principal", "n/a", List.of());
		}

		@Override
		public String getName() {
			return null;
		}
	}
}

@ExtendWith(MockitoExtension.class)
class JdbcOAuth2AuthorizationQueryServiceTest {

	@Mock
	private org.springframework.jdbc.core.JdbcOperations jdbcOperations;

	@InjectMocks
	private com.eskcti.algashop.authorization_server.infrastructure.persistence.JdbcOAuth2AuthorizationQueryService service;

	@Test
	void findAuthorizationIds_queriesByPrincipalName() {
		UUID first = UUID.randomUUID();
		UUID second = UUID.randomUUID();
		when(jdbcOperations.queryForList(anyString(), eq(String.class), eq("alice@algashop.com")))
				.thenReturn(List.of(first.toString(), second.toString()));

		List<String> ids = service.findAuthorizationIds("alice@algashop.com");

		assertThat(ids).containsExactly(first.toString(), second.toString());
		verify(jdbcOperations).queryForList(
				"SELECT id FROM oauth2_authorization WHERE principal_name = ?",
				String.class,
				"alice@algashop.com");
	}
}
