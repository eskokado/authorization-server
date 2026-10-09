package com.eskcti.algashop.authorization_server.infrastructure.security.userinfo;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthUserDetailService implements UserDetailsService {

	private final AuthUserRepository authUserRepository;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		AuthUser authUser = authUserRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("User not found " + email));

		return User.withUsername(email)
				.password(authUser.getPassword())
				.disabled(!authUser.isEnabled())
				.build();
	}
}
