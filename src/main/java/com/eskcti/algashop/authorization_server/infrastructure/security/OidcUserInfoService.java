package com.eskcti.algashop.authorization_server.infrastructure.security;

import com.eskcti.algashop.authorization_server.domain.model.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

	private final AuthUserRepository authUserRepository;

	public OidcUserInfo loadUser(String email) {
		AuthUser authUser = authUserRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("User not found " + email));

		return OidcUserInfo.builder()
				.subject(authUser.getId().toString())
				.name(authUser.getName())
				.email(authUser.getEmail())
				.claim("type", authUser.getType().name())
				.claim("created_at", String.valueOf(authUser.getCreatedAt().toEpochSecond()))
				.build();
	}

}
