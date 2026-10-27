package com.eskcti.algashop.authorization_server.application.user.management;

import com.eskcti.algashop.authorization_server.application.user.UserAccountProperties;
import com.eskcti.algashop.authorization_server.application.user.mail.AuthUserMailSender;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserNotFoundException;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserPasswordManager;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import com.eskcti.algashop.authorization_server.domain.model.user.VerificationTokenHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.newUser;
import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.verified;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordManagementApplicationServiceTest {

	private static final String PLAIN_TOKEN = "plain-token";
	private static final String HASHED_TOKEN = "hashed-plain-token";
	private static final Duration PASSWORD_RESET_TTL = Duration.ofHours(2);

	@Mock
	private AuthUserRepository authUserRepository;

	@Mock
	private AuthUserPasswordManager passwordManager;

	@Mock
	private AuthUserMailSender authUserMailSender;

	private final VerificationTokenHasher tokenHasher = new VerificationTokenHasher() {
		@Override
		public String generate() {
			return PLAIN_TOKEN;
		}

		@Override
		public String hash(String plainToken) {
			return "hashed-" + plainToken;
		}

		@Override
		public boolean isEqual(String hashed, String plainToken) {
			return hash(plainToken).equals(hashed);
		}
	};

	private PasswordManagementApplicationService service;

	@BeforeEach
	void setUp() {
		UserAccountProperties userAccountProperties = new UserAccountProperties();
		UserAccountProperties.PasswordToken token = new UserAccountProperties.PasswordToken();
		token.setActivationTtl(Duration.ofHours(24));
		token.setPasswordResetTtl(PASSWORD_RESET_TTL);
		userAccountProperties.setToken(token);

		service = new PasswordManagementApplicationService(
				authUserRepository, userAccountProperties, passwordManager, tokenHasher, authUserMailSender);
	}

	@Test
	void changePasswordWithToken_updatesPasswordClearsTokenAndVerifiesEmail() {
		AuthUser user = unverifiedUserWithToken();
		when(authUserRepository.findByVerificationToken(HASHED_TOKEN)).thenReturn(Optional.of(user));
		when(passwordManager.encrypt("new-password")).thenReturn("new-encrypted-password");

		service.changePasswordWithToken(PLAIN_TOKEN, "new-password");

		assertThat(user.getPassword()).isEqualTo("new-encrypted-password");
		assertThat(user.isEmailVerified()).isTrue();
		assertThat(user.getVerificationToken()).isNull();
		assertThat(user.getVerificationTokenExpirationDate()).isNull();
		verify(authUserRepository).save(user);
	}

	@Test
	void changePasswordWithToken_keepsEmailVerifiedWhenAlreadyVerified() {
		AuthUser user = verified(unverifiedUserWithToken());
		when(authUserRepository.findByVerificationToken(HASHED_TOKEN)).thenReturn(Optional.of(user));
		when(passwordManager.encrypt("new-password")).thenReturn("new-encrypted-password");

		service.changePasswordWithToken(PLAIN_TOKEN, "new-password");

		assertThat(user.isEmailVerified()).isTrue();
		assertThat(user.getPassword()).isEqualTo("new-encrypted-password");
		verify(authUserRepository).save(user);
	}

	@Test
	void changePasswordWithToken_rejectsInvalidToken() {
		AuthUser user = unverifiedUserWithToken();
		when(authUserRepository.findByVerificationToken("hashed-wrong-token")).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> service.changePasswordWithToken("wrong-token", "new-password"))
				.isInstanceOf(AccessDeniedException.class)
				.hasMessageContaining("Invalid token");

		verify(passwordManager, never()).encrypt(any());
		verify(authUserRepository, never()).save(any());
	}

	@Test
	void changePasswordWithToken_rejectsExpiredToken() {
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.CUSTOMER);
		user.generateVerificationToken(Duration.ofHours(-1), tokenHasher);
		when(authUserRepository.findByVerificationToken(HASHED_TOKEN)).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> service.changePasswordWithToken(PLAIN_TOKEN, "new-password"))
				.isInstanceOf(AccessDeniedException.class)
				.hasMessageContaining("Token has expired");

		verify(authUserRepository, never()).save(any());
	}

	@Test
	void changePasswordWithToken_rejectsTokenWithoutExpiration() {
		AuthUser user = unverifiedUserWithToken();
		clearVerificationTokenExpiration(user);
		when(authUserRepository.findByVerificationToken(HASHED_TOKEN)).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> service.changePasswordWithToken(PLAIN_TOKEN, "new-password"))
				.isInstanceOf(AccessDeniedException.class)
				.hasMessageContaining("Token has expired");

		verify(authUserRepository, never()).save(any());
	}

	@Test
	void changePasswordWithToken_throwsNotFoundWhenTokenIsUnknown() {
		when(authUserRepository.findByVerificationToken(HASHED_TOKEN)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.changePasswordWithToken(PLAIN_TOKEN, "new-password"))
				.isInstanceOf(AuthUserNotFoundException.class)
				.hasMessageContaining("verification token");

		verify(authUserRepository, never()).save(any());
	}

	@Test
	void requestPasswordChangeByUserId_sendsMailAndPersistsToken() {
		UUID userId = UUID.randomUUID();
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(user));

		OffsetDateTime before = OffsetDateTime.now();
		service.requestPasswordChange(userId);
		OffsetDateTime after = OffsetDateTime.now();

		assertThat(user.getVerificationToken()).isEqualTo(HASHED_TOKEN);
		assertThat(user.getVerificationTokenExpirationDate())
				.isBetween(before.plus(PASSWORD_RESET_TTL), after.plus(PASSWORD_RESET_TTL));
		verify(authUserMailSender).sendPasswordChangeEmail(user, PLAIN_TOKEN);
		verify(authUserRepository).save(user);
	}

	@Test
	void requestPasswordChangeByUserId_throwsWhenUserDoesNotExist() {
		UUID userId = UUID.randomUUID();
		when(authUserRepository.findById(userId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.requestPasswordChange(userId))
				.isInstanceOf(AuthUserNotFoundException.class)
				.hasMessageContaining(userId.toString());

		verify(authUserMailSender, never()).sendPasswordChangeEmail(any(), any());
		verify(authUserRepository, never()).save(any());
	}

	@Test
	void requestPasswordChangeByEmail_sendsMailAndPersistsToken() {
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		when(authUserRepository.findByEmail("alice@algashop.com")).thenReturn(Optional.of(user));

		service.requestPasswordChange("alice@algashop.com");

		assertThat(user.getVerificationToken()).isEqualTo(HASHED_TOKEN);
		verify(authUserMailSender).sendPasswordChangeEmail(user, PLAIN_TOKEN);
		verify(authUserRepository).save(user);
	}

	@Test
	void requestPasswordChangeByEmail_throwsWhenEmailDoesNotExist() {
		when(authUserRepository.findByEmail("ghost@algashop.com")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.requestPasswordChange("ghost@algashop.com"))
				.isInstanceOf(AuthUserNotFoundException.class)
				.hasMessageContaining("ghost@algashop.com");

		verify(authUserMailSender, never()).sendPasswordChangeEmail(any(), any());
		verify(authUserRepository, never()).save(any());
	}

	private AuthUser unverifiedUserWithToken() {
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.CUSTOMER);
		user.generateVerificationToken(PASSWORD_RESET_TTL, tokenHasher);
		return user;
	}

	private void clearVerificationTokenExpiration(AuthUser user) {
		try {
			var field = AuthUser.class.getDeclaredField("verificationTokenExpirationDate");
			field.setAccessible(true);
			field.set(user, null);
		} catch (ReflectiveOperationException e) {
			throw new IllegalStateException(e);
		}
	}
}
