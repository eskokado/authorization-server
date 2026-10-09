package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.application.security.SecurityCheckApplicationService;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserQueryService;
import com.eskcti.algashop.authorization_server.infrastructure.security.check.SecurityAnnotations;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
public class MyUserController {

	private final SecurityCheckApplicationService securityCheck;
	private final AuthUserQueryService queryService;

	@GetMapping
	@SecurityAnnotations.CanAccessOwnProfile
	public AuthUserOutput getMe() {
		return queryService.findById(securityCheck.getAuthenticatedUserId());
	}

}
