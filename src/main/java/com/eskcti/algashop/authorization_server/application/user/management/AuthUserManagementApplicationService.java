package com.eskcti.algashop.authorization_server.application.user.management;

import com.eskcti.algashop.authorization_server.application.security.SecurityCheckApplicationService;
import com.eskcti.algashop.authorization_server.application.user.UserAccountProperties;
import com.eskcti.algashop.authorization_server.application.user.mail.AuthUserMailSender;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserNotFoundException;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserPasswordManager;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.VerificationTokenHasher;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthUserManagementApplicationService {

	private final AuthUserRepository authUserRepository;
	private final SecurityCheckApplicationService securityCheck;
	private final UserAccountProperties userAccountProperties;
	private final AuthUserPasswordManager passwordManager;
	private final VerificationTokenHasher tokenHasher;

	private final AuthUserMailSender authUserMailSender;

	public AuthUserOutput create(AuthUserInput input) {
		if (!securityCheck.canRegisterUserOfType(input.getType())) {
			throw new AccessDeniedException("Cannot register user of type " + input.getType());
		}

		if (authUserRepository.existsByEmail(input.getEmail())) {
			throw new AuthUserEmailAlreadyInUseException(input.getEmail());
		}

		AuthUser user = AuthUser.brandNew(
				input.getEmail(),
				input.getName(),
				input.getType(),
				passwordManager);

		String plainToken = user.generateVerificationToken(userAccountProperties.getToken().getActivationTtl(),
				tokenHasher);

		authUserMailSender.sendActivationEmail(user, plainToken);

		return AuthUserOutput.from(authUserRepository.save(user));
	}

	public AuthUserOutput update(UUID userId, AuthUserUpdateInput input) {
		AuthUser user = authUserRepository.findById(userId)
				.orElseThrow(() -> new AuthUserNotFoundException(userId));

		verifyCanEditUser(user, input);

		user.setName(input.getName());
		user.setType(input.getType());
		user.setEnabled(input.isEnabled());

		return AuthUserOutput.from(authUserRepository.save(user));
	}

	private void verifyCanEditUser(AuthUser authUser, AuthUserUpdateInput input) {
		if (!securityCheck.canEditUser(authUser.getType(), authUser.getId())) {
			throw new AccessDeniedException("Cannot edit user of type " + authUser.getType());
		}

		if (!securityCheck.canChangeUserType(authUser.getType(), input.getType())) {
			throw new AccessDeniedException("Cannot change user type to " + input.getType());
		}
	}

	public void delete(UUID userId) {
		AuthUser user = authUserRepository.findById(userId)
				.orElseThrow(() -> new AuthUserNotFoundException(userId));
		user.anonymize();
		authUserRepository.save(user);
	}
}
