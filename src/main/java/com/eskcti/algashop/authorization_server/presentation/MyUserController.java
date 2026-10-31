package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.application.security.SecurityChecks;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserManagementApplicationService;
import com.eskcti.algashop.authorization_server.application.user.management.MyUserUpdateInput;
import com.eskcti.algashop.authorization_server.application.user.management.PasswordManagementApplicationService;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserQueryService;
import com.eskcti.algashop.authorization_server.infrastructure.security.check.SecurityAnnotations;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
public class MyUserController {

	private final SecurityChecks securityCheck;
	private final AuthUserQueryService queryService;
	private final AuthUserManagementApplicationService managementService;
	private final PasswordManagementApplicationService passwordManagementApplicationService;

	@GetMapping
	@SecurityAnnotations.CanAccessOwnProfile
	public AuthUserOutput getMe() {
		return queryService.findById(securityCheck.getAuthenticatedUserId());
	}

	@PutMapping
	@SecurityAnnotations.CanAccessOwnProfile
	public AuthUserOutput updateMe(@RequestBody @Valid MyUserUpdateInput input) {
		return managementService.update(securityCheck.getAuthenticatedUserId(), input);
	}

	@DeleteMapping
	@ResponseStatus(HttpStatus.NO_CONTENT)
	@SecurityAnnotations.CanDeleteOwnProfile
	public void deleteMe() {
		managementService.delete(securityCheck.getAuthenticatedUserId());
	}

	@PostMapping("/password-change")
	@SecurityAnnotations.CanAccessOwnProfile
	public void requestPasswordChange() {
		passwordManagementApplicationService.requestPasswordChange(securityCheck.getAuthenticatedUserId());
	}

}
