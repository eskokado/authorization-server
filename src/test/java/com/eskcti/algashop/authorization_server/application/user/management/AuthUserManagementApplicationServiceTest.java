package com.eskcti.algashop.authorization_server.application.user.management;

import com.eskcti.algashop.authorization_server.application.user.query.AuthUserNotFoundException;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.domain.model.DomainException;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

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
	private PasswordEncoder passwordEncoder;

	private AuthUserManagementApplicationService service;

	@BeforeEach
	void setUp() {
		service = new AuthUserManagementApplicationService(authUserRepository, passwordEncoder);
	}

	@Test
	void create_persistsUserWithEncodedTemporaryPassword() {
		when(authUserRepository.existsByEmail("alice@algashop.com")).thenReturn(false);
		when(passwordEncoder.encode(anyString())).thenReturn("encoded-hash");
		when(authUserRepository.save(any(AuthUser.class)))
				.thenAnswer(invocation -> invocation.getArgument(0));

		AuthUserOutput output = service.create(AuthUserInput.builder()
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.MANAGER)
				.build());

		ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
		verify(authUserRepository).save(captor.capture());
		AuthUser saved = captor.getValue();

		assertThat(saved.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(saved.getName()).isEqualTo("Alice");
		assertThat(saved.getType()).isEqualTo(AuthUserType.MANAGER);
		assertThat(saved.getPassword()).isEqualTo("encoded-hash");
		assertThat(saved.isEnabled()).isTrue();
		assertThat(output.getId()).isEqualTo(saved.getId());
		assertThat(output.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(output.isEnabled()).isTrue();
	}

	@Test
	void create_rejectsDuplicatedEmail() {
		when(authUserRepository.existsByEmail("alice@algashop.com")).thenReturn(true);

		assertThatThrownBy(() -> service.create(AuthUserInput.builder()
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.MANAGER)
				.build()))
				.isInstanceOf(AuthUserEmailAlreadyInUseException.class)
				.hasMessageContaining("alice@algashop.com");

		verify(authUserRepository, never()).save(any());
		verify(passwordEncoder, never()).encode(anyString());
	}

	@Test
	void update_appliesNewValuesOnExistingUser() {
		UUID userId = UUID.randomUUID();
		AuthUser existing = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(existing));
		when(authUserRepository.save(any(AuthUser.class)))
				.thenAnswer(invocation -> invocation.getArgument(0));

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
		AuthUser customer = AuthUser.brandNew("bob@algashop.com", "Bob", AuthUserType.CUSTOMER, "hash");
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(customer));

		assertThatThrownBy(() -> service.update(userId, AuthUserUpdateInput.builder()
				.name("Bob")
				.type(AuthUserType.MANAGER)
				.enabled(true)
				.build()))
				.isInstanceOf(DomainException.class);
	}

	@Test
	void delete_anonymizesUserInsteadOfRemovingRecord() {
		UUID userId = UUID.randomUUID();
		AuthUser existing = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");
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
