package com.eskcti.algashop.authorization_server.application.user.query;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthUserQueryService {

	private final AuthUserRepository authUserRepository;

	public AuthUserOutput findById(UUID userId) {
		return authUserRepository.findById(userId)
				.map(AuthUserOutput::from)
				.orElseThrow(()-> new AuthUserNotFoundException(userId));
	}

}
