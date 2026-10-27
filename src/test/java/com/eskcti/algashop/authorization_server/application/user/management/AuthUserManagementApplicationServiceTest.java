package com.eskcti.algashop.authorization_server.application.user.management;

import com.eskcti.algashop.authorization_server.application.security.SecurityCheckApplicationService;
import com.eskcti.algashop.authorization_server.application.user.UserAccountProperties;
import com.eskcti.algashop.authorization_server.application.user.mail.AuthUserMailSender;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserNotFoundException;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.domain.model.DomainException;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserPasswordManager;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.domain.model.user.VerificationTokenHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.newUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthUserManagementApplicationServiceTest {

	@Mock
	private AuthUserRepository authUserRepository;

	@Mock
	private AuthUserPasswordManager passwordManager;

	@Mock
	private VerificationTokenHasher tokenHasher;

	@Mock
	private SecurityCheckApplicationService securityCheck;

	@Mock
	private AuthUserMailSender authUserMailSender;

	private AuthUserManagementApplicationService service;

	@BeforeEach
	void setUp() {
		UserAccountProperties userAccountProperties = new UserAccountProperties();
		UserAccountProperties.PasswordToken token = new UserAccountProperties.PasswordToken();
		token.setActivationTtl(Duration.ofHours(24));
		token.setPasswordResetTtl(Duration.ofHours(2));
		userAccountProperties.setToken(token);

		service = new AuthUserManagementApplicationService(
				authUserRepository, securityCheck, userAccountProperties, passwordManager, tokenHasher,
				authUserMailSender);
	}

	@Test
	void create_throwsWhenSecurityCheckDeniesRegistration() {
		when(securityCheck.canRegisterUserOfType(AuthUserType.MANAGER)).thenReturn(false);

		assertThatThrownBy(() -> service.create(AuthUserInput.builder()
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.MANAGER)
				.build()))
				.isInstanceOf(AccessDeniedException.class);

		verify(authUserRepository, never()).save(any());
		verify(passwordManager, never()).encrypt(anyString());
	}

	@Test
	void create_persistsUserWithEncodedTemporaryPasswordAndVerificationToken() {
		when(securityCheck.canRegisterUserOfType(AuthUserType.MANAGER)).thenReturn(true);
		when(authUserRepository.existsByEmail("alice@algashop.com")).thenReturn(false);
		when(passwordManager.generates()).thenReturn("temp-password");
		when(passwordManager.encrypt("temp-password")).thenReturn("encoded-hash");
		when(tokenHasher.generate()).thenReturn("plain-token");
		when(tokenHasher.hash("plain-token")).thenReturn("hashed-token");
		when(authUserRepository.save(any(AuthUser.class)))
				.thenAnswer(invocation -> invocation.getArgument(0));

		OffsetDateTime before = OffsetDateTime.now();
		AuthUserOutput output = service.create(AuthUserInput.builder()
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.MANAGER)
				.build());
		OffsetDateTime after = OffsetDateTime.now();

		ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
		verify(authUserRepository).save(captor.capture());
		AuthUser saved = captor.getValue();

		assertThat(saved.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(saved.getName()).isEqualTo("Alice");
		assertThat(saved.getType()).isEqualTo(AuthUserType.MANAGER);
		assertThat(saved.getPassword()).isEqualTo("encoded-hash");
		assertThat(saved.isEnabled()).isTrue();
		assertThat(saved.isEmailVerified()).isFalse();
		assertThat(saved.getVerificationToken()).isEqualTo("hashed-token");
		assertThat(saved.getVerificationTokenExpirationDate())
				.isBetween(before.plusHours(24), after.plusHours(24));
		assertThat(output.getId()).isEqualTo(saved.getId());
		assertThat(output.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(output.isEnabled()).isTrue();
		verify(authUserMailSender).sendActivationEmail(saved, "plain-token");
	}

	@Test
	void create_rejectsDuplicatedEmail() {
		when(securityCheck.canRegisterUserOfType(AuthUserType.MANAGER)).thenReturn(true);
		when(authUserRepository.existsByEmail("alice@algashop.com")).thenReturn(true);

		assertThatThrownBy(() -> service.create(AuthUserInput.builder()
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.MANAGER)
				.build()))
				.isInstanceOf(AuthUserEmailAlreadyInUseException.class)
				.hasMessageContaining("alice@algashop.com");

		verify(authUserRepository, never()).save(any());
		verify(passwordManager, never()).encrypt(anyString());
	}

	@Test
	void update_appliesNewValuesOnExistingUser() {
		UUID userId = UUID.randomUUID();
		AuthUser existing = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(existing));
		when(authUserRepository.save(any(AuthUser.class)))
				.thenAnswer(invocation -> invocation.getArgument(0));
		when(securityCheck.canEditUser(AuthUserType.MANAGER, existing.getId())).thenReturn(true);
		when(securityCheck.canChangeUserType(AuthUserType.MANAGER, AuthUserType.OPERATOR)).thenReturn(true);

		AuthUserOutput output = service.update(userId, AuthUserUpdateInput.builder()
				.name("Alice Updated")
				.type(AuthUserType.OPERATOR)
				.enabled(false)
				.build());

		assertThat(output.getName()).isEqualTo("Alice Updated");
		assertThat(output.getType()).isEqualTo(AuthUserType.OPERATOR);
		assertThat(output.isEnabled()).isFalse();
		verify(authUserRepository).save(existing);
	}

	@Test
	void update_throwsWhenUserDoesNotExist() {
		UUID userId = UUID.randomUUID();
		when(authUserRepository.findById(userId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.update(userId, AuthUserUpdateInput.builder()
				.name("Ghost")
				.type(AuthUserType.CUSTOMER)
				.enabled(true)
				.build()))
				.isInstanceOf(AuthUserNotFoundException.class)
				.hasMessageContaining(userId.toString());
	}

	@Test
	void update_rejectsTypeChangeOnCustomer() {
		UUID userId = UUID.randomUUID();
		AuthUser customer = newUser("bob@algashop.com", "Bob", AuthUserType.CUSTOMER);
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(customer));
		when(securityCheck.canEditUser(AuthUserType.CUSTOMER, customer.getId())).thenReturn(true);
		when(securityCheck.canChangeUserType(AuthUserType.CUSTOMER, AuthUserType.MANAGER)).thenReturn(true);

		assertThatThrownBy(() -> service.update(userId, AuthUserUpdateInput.builder()
				.name("Bob")
				.type(AuthUserType.MANAGER)
				.enabled(true)
				.build()))
				.isInstanceOf(DomainException.class);
	}

	@Test
	void update_throwsWhenSecurityCheckDeniesEditing() {
		UUID userId = UUID.randomUUID();
		AuthUser existing = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(existing));
		when(securityCheck.canEditUser(AuthUserType.MANAGER, existing.getId())).thenReturn(false);

		assertThatThrownBy(() -> service.update(userId, AuthUserUpdateInput.builder()
				.name("Alice Updated")
				.type(AuthUserType.OPERATOR)
				.enabled(true)
				.build()))
				.isInstanceOf(AccessDeniedException.class);

		verify(authUserRepository, never()).save(any());
	}

	@Test
	void update_throwsWhenSecurityCheckDeniesTypeChange() {
		UUID userId = UUID.randomUUID();
		AuthUser existing = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(existing));
		when(securityCheck.canEditUser(AuthUserType.MANAGER, existing.getId())).thenReturn(true);
		when(securityCheck.canChangeUserType(AuthUserType.MANAGER, AuthUserType.OPERATOR)).thenReturn(false);

		assertThatThrownBy(() -> service.update(userId, AuthUserUpdateInput.builder()
				.name("Alice Updated")
				.type(AuthUserType.OPERATOR)
				.enabled(true)
				.build()))
				.isInstanceOf(AccessDeniedException.class);

		verify(authUserRepository, never()).save(any());
	}

	@Test
	void delete_anonymizesUserInsteadOfRemovingRecord() {
		UUID userId = UUID.randomUUID();
		AuthUser existing = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(existing));
		when(authUserRepository.save(any(AuthUser.class)))
				.thenAnswer(invocation -> invocation.getArgument(0));

		service.delete(userId);

		ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
		verify(authUserRepository).save(captor.capture());
		assertThat(captor.getValue().getName()).isEqualTo("Anonymized User");
		assertThat(captor.getValue().isEnabled()).isFalse();
	}

	@Test
	void delete_throwsWhenUserDoesNotExist() {
		UUID userId = UUID.randomUUID();
		when(authUserRepository.findById(userId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.delete(userId))
				.isInstanceOf(AuthUserNotFoundException.class);

		verify(authUserRepository, never()).save(any());
	}
}
