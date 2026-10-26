package com.eskcti.algashop.authorization_server.infrastructure.security.password;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserPasswordManager;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthUserPasswordManagerImpl implements AuthUserPasswordManager {

	private final PasswordEncoder passwordEncoder;

	@Override
	public String generates() {
		return RandomStringUtils.secure().next(12);
	}

	@Override
	public String encrypt(String plainPassword) {
		return passwordEncoder.encode(plainPassword);
	}

	@Override
	public boolean matches(String encryptedPassword, String plainPassword) {
		return passwordEncoder.matches(plainPassword, encryptedPassword);
	}
}
