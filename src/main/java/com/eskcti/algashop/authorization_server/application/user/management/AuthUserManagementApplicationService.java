package com.eskcti.algashop.authorization_server.application.user.management;

import com.eskcti.algashop.authorization_server.application.user.query.AuthUserNotFoundException;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthUserManagementApplicationService {

	private final AuthUserRepository authUserRepository;
	private final PasswordEncoder passwordEncoder;

	public AuthUserOutput create(AuthUserInput input) {
		if (authUserRepository.existsByEmail(input.getEmail())) {
			throw new AuthUserEmailAlreadyInUseException(input.getEmail());
		}

		String tempPassword = RandomStringUtils.secure().nextAlphanumeric(12);

		System.out.println(tempPassword); //todo send via email

		String passwordHash = passwordEncoder.encode(tempPassword);

		AuthUser user = AuthUser.brandNew(
				input.getEmail(),
				input.getName(),
				input.getType(),
				passwordHash
		);

		return AuthUserOutput.from(authUserRepository.save(user));
	}

	public AuthUserOutput update(UUID userId, AuthUserUpdateInput input) {
		AuthUser user = authUserRepository.findById(userId)
				.orElseThrow(() -> new AuthUserNotFoundException(userId));

		user.setName(input.getName());
		user.setType(input.getType());
		user.setEnabled(input.isEnabled());

		return AuthUserOutput.from(authUserRepository.save(user));
	}

	public void delete(UUID userId) {
		AuthUser user = authUserRepository.findById(userId)
				.orElseThrow(() -> new AuthUserNotFoundException(userId));
		user.anonymize();
		authUserRepository.save(user);
	}

}
