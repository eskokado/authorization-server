package com.eskcti.algashop.authorization_server.infrastructure.security.check;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Arrays;
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

	@Test
	void canRegisterUserOfType_falseWithoutAuthentication() {
		assertThat(service.canRegisterUserOfType(AuthUserType.CUSTOMER)).isFalse();
	}

	@Test
	void canRegisterUserOfType_falseWithoutUsersWriteScope() {
		authorize(machineJwt("algashop-ordering-service"), "SCOPE_users:read");

		assertThat(service.canRegisterUserOfType(AuthUserType.CUSTOMER)).isFalse();
	}

	@Test
	void canRegisterUserOfType_trueForMachineCreatingCustomer() {
		authorize(machineJwt("algashop-ecommerce-web"), "SCOPE_users:write");

		assertThat(service.canRegisterUserOfType(AuthUserType.CUSTOMER)).isTrue();
	}

	@Test
	void canRegisterUserOfType_falseForMachineCreatingManager() {
		authorize(machineJwt("algashop-ecommerce-web"), "SCOPE_users:write");

		assertThat(service.canRegisterUserOfType(AuthUserType.MANAGER)).isFalse();
	}

	@Test
	void canRegisterUserOfType_falseForHumanCreatingCustomer() {
		authorize(userJwt(UUID.randomUUID().toString()), "SCOPE_users:write");

		assertThat(service.canRegisterUserOfType(AuthUserType.CUSTOMER)).isFalse();
	}

	@Test
	void canRegisterUserOfType_trueForManagerCreatingManager() {
		authorize(userJwt(UUID.randomUUID().toString()), "SCOPE_users:write", "ROLE_MANAGER");

		assertThat(service.canRegisterUserOfType(AuthUserType.MANAGER)).isTrue();
	}

	@Test
	void canRegisterUserOfType_trueForManagerCreatingOperator() {
		authorize(userJwt(UUID.randomUUID().toString()), "SCOPE_users:write", "ROLE_MANAGER");

		assertThat(service.canRegisterUserOfType(AuthUserType.OPERATOR)).isTrue();
	}

	@Test
	void canRegisterUserOfType_falseForManagerCreatingCustomer() {
		authorize(userJwt(UUID.randomUUID().toString()), "SCOPE_users:write", "ROLE_MANAGER");

		assertThat(service.canRegisterUserOfType(AuthUserType.CUSTOMER)).isFalse();
	}

	@Test
	void canRegisterUserOfType_falseForHumanWithoutManagerRole() {
		authorize(userJwt(UUID.randomUUID().toString()), "SCOPE_users:write");

		assertThat(service.canRegisterUserOfType(AuthUserType.OPERATOR)).isFalse();
	}

	@Test
	void canRegisterUserOfType_falseForManagerRegisteringUnknownType() {
		authorize(userJwt(UUID.randomUUID().toString()), "SCOPE_users:write", "ROLE_MANAGER");

		assertThat(service.canRegisterUserOfType(null)).isFalse();
	}

	@Test
	void canEditUser_falseForMachineClient() {
		authorize(machineJwt("algashop-ecommerce-web"));

		assertThat(service.canEditUser(AuthUserType.CUSTOMER, UUID.randomUUID())).isFalse();
	}

	@Test
	void canEditUser_trueWhenUserEditsOwnProfile() {
		UUID userId = UUID.randomUUID();
		authorize(userJwt(userId.toString()));

		assertThat(service.canEditUser(AuthUserType.CUSTOMER, userId)).isTrue();
	}

	@Test
	void canEditUser_falseWhenSubjectIsNotAValidUuid() {
		authorize(userJwt("not-a-uuid"));

		assertThat(service.canEditUser(AuthUserType.CUSTOMER, UUID.randomUUID())).isFalse();
	}

	@Test
	void canEditUser_trueForManagerEditingManager() {
		UUID targetUserId = UUID.randomUUID();
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canEditUser(AuthUserType.MANAGER, targetUserId)).isTrue();
	}

	@Test
	void canEditUser_trueForManagerEditingOperator() {
		UUID targetUserId = UUID.randomUUID();
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canEditUser(AuthUserType.OPERATOR, targetUserId)).isTrue();
	}

	@Test
	void canEditUser_falseForManagerEditingCustomer() {
		UUID targetUserId = UUID.randomUUID();
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canEditUser(AuthUserType.CUSTOMER, targetUserId)).isFalse();
	}

	@Test
	void canEditUser_falseForNonManagerEditingAnotherUser() {
		UUID targetUserId = UUID.randomUUID();
		authorize(userJwt(UUID.randomUUID().toString()));

		assertThat(service.canEditUser(AuthUserType.CUSTOMER, targetUserId)).isFalse();
	}

	@Test
	void canChangeUserType_trueWhenTypeIsUnchanged() {
		authorize(userJwt(UUID.randomUUID().toString()));

		assertThat(service.canChangeUserType(AuthUserType.CUSTOMER, AuthUserType.CUSTOMER)).isTrue();
	}

	@Test
	void canChangeUserType_trueForManagerPromotingOperator() {
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canChangeUserType(AuthUserType.OPERATOR, AuthUserType.MANAGER)).isTrue();
	}

	@Test
	void canChangeUserType_trueForManagerDemotingManager() {
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canChangeUserType(AuthUserType.MANAGER, AuthUserType.OPERATOR)).isTrue();
	}

	@Test
	void canChangeUserType_falseForManagerChangingToCustomer() {
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canChangeUserType(AuthUserType.MANAGER, AuthUserType.CUSTOMER)).isFalse();
	}

	@Test
	void canChangeUserType_falseForManagerChangingOperatorToCustomer() {
		authorize(userJwt(UUID.randomUUID().toString()), "ROLE_MANAGER");

		assertThat(service.canChangeUserType(AuthUserType.OPERATOR, AuthUserType.CUSTOMER)).isFalse();
	}

	@Test
	void canChangeUserType_falseForNonManagerChangingType() {
		authorize(userJwt(UUID.randomUUID().toString()));

		assertThat(service.canChangeUserType(AuthUserType.CUSTOMER, AuthUserType.OPERATOR)).isFalse();
	}

	@Test
	void canChangeUserType_falseWithoutAuthentication() {
		assertThat(service.canChangeUserType(AuthUserType.CUSTOMER, AuthUserType.OPERATOR)).isFalse();
	}

	private void authorize(Jwt jwt) {
		authorize(jwt, "SCOPE_users:read");
	}

	private void authorize(Jwt jwt, String... authorities) {
		List<GrantedAuthority> grantedAuthorities = Arrays.stream(authorities)
				.map(authority -> (GrantedAuthority) () -> authority)
				.toList();
		SecurityContextHolder.getContext().setAuthentication(
				new JwtAuthenticationToken(jwt, grantedAuthorities));
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
