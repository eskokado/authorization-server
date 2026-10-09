package com.eskcti.algashop.authorization_server.infrastructure.security.check;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuth2SecurityCheckApplicationServiceImplTest {

	private final OAuth2SecurityCheckApplicationServiceImpl service =
			new OAuth2SecurityCheckApplicationServiceImpl();

	@AfterEach
	void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void getAuthenticatedUserId_returnsSubjectWhenItIsAUserUuid() {
		UUID userId = UUID.randomUUID();
		authorize(userJwt(userId.toString()));

		assertThat(service.getAuthenticatedUserId()).isEqualTo(userId);
	}

	@Test
	void getAuthenticatedUserId_failsWhenNoAuthentication() {
		assertThatThrownBy(service::getAuthenticatedUserId)
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("No authentication found");
	}

	@Test
	void getAuthenticatedUserId_deniesMachineClients() {
		authorize(machineJwt("algashop-ordering-service"));

		assertThatThrownBy(service::getAuthenticatedUserId)
				.isInstanceOf(AccessDeniedException.class)
				.hasMessageContaining("Machine users");
	}

	@Test
	void getAuthenticatedUserId_deniesNonUuidSubject() {
		authorize(userJwt("not-a-uuid"));

		assertThatThrownBy(service::getAuthenticatedUserId)
				.isInstanceOf(AccessDeniedException.class)
				.hasMessageContaining("Invalid user ID in JWT subject");
	}

	@Test
	void isAuthenticated_falseWhenSecurityContextIsEmpty() {
		assertThat(service.isAuthenticated()).isFalse();
	}

	@Test
	void isAuthenticated_trueForAuthenticatedToken() {
		UUID userId = UUID.randomUUID();
		authorize(userJwt(userId.toString()));

		assertThat(service.isAuthenticated()).isTrue();
	}

	@Test
	void isMachineAuthenticated_trueWhenAudienceMatchesSubject() {
		authorize(machineJwt("algashop-ordering-service"));

		assertThat(service.isMachineAuthenticated()).isTrue();
	}

	@Test
	void isMachineAuthenticated_falseForHumanJwt() {
		UUID userId = UUID.randomUUID();
		authorize(userJwt(userId.toString()));

		assertThat(service.isMachineAuthenticated()).isFalse();
	}

	@Test
	void isMachineAuthenticated_falseWhenAudienceIsMissing() {
		UUID userId = UUID.randomUUID();
		Jwt jwt = Jwt.withTokenValue("token")
				.header("alg", "none")
				.subject(userId.toString())
				.build();
		authorize(jwt);

		assertThat(service.isMachineAuthenticated()).isFalse();
	}

	@Test
	void isMachineAuthenticated_falseWhenNoAuthentication() {
		assertThat(service.isMachineAuthenticated()).isFalse();
	}

	@Test
	void isMachineAuthenticated_falseWhenPrincipalIsNotJwt() {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("alice", "password", List.of()));

		assertThat(service.isMachineAuthenticated()).isFalse();
	}

	@Test
	void canAccessOwnProfile_trueForHumanUser() {
		UUID userId = UUID.randomUUID();
		authorize(userJwt(userId.toString()));

		assertThat(service.canAccessOwnProfile()).isTrue();
	}

	@Test
	void canAccessOwnProfile_falseForMachineClient() {
		authorize(machineJwt("algashop-ordering-service"));

		assertThat(service.canAccessOwnProfile()).isFalse();
	}

	@Test
	void canAccessOwnProfile_falseWithoutAuthentication() {
		assertThat(service.canAccessOwnProfile()).isFalse();
	}

	private void authorize(Jwt jwt) {
		SecurityContextHolder.getContext().setAuthentication(
				new JwtAuthenticationToken(jwt, List.of(() -> "SCOPE_users:read")));
	}

	private Jwt userJwt(String subject, String... audience) {
		List<String> audiences = audience.length > 0 ? List.of(audience) : List.of("algashop-ecommerce-web");
		return Jwt.withTokenValue("token")
				.header("alg", "none")
				.subject(subject)
				.audience(audiences)
				.build();
	}

	private Jwt machineJwt(String clientId) {
		return Jwt.withTokenValue("token")
				.header("alg", "none")
				.subject(clientId)
				.audience(List.of(clientId))
				.build();
	}
}
