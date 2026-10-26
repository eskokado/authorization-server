package com.eskcti.algashop.authorization_server.infrastructure.security.password;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthUserPasswordManagerImplTest {

	@Mock
	private PasswordEncoder passwordEncoder;

	@InjectMocks
	private AuthUserPasswordManagerImpl manager;

	@Test
	void generates_returnsRandomPassword() {
		String first = manager.generates();
		String second = manager.generates();

		assertThat(first).hasSize(12).isNotBlank();
		assertThat(second).hasSize(12).isNotBlank();
		assertThat(first).isNotEqualTo(second);
	}

	@Test
	void encrypt_delegatesToPasswordEncoder() {
		when(passwordEncoder.encode("plain")).thenReturn("encoded");

		assertThat(manager.encrypt("plain")).isEqualTo("encoded");
	}

	@Test
	void matches_delegatesToPasswordEncoder() {
		when(passwordEncoder.matches("plain", "encoded")).thenReturn(true);

		assertThat(manager.matches("encoded", "plain")).isTrue();
	}
}
