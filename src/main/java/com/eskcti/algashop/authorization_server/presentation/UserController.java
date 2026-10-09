package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.application.user.management.AuthUserInput;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserManagementApplicationService;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserUpdateInput;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserFilter;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserQueryService;
import com.eskcti.algashop.authorization_server.application.user.query.PageModel;
import com.eskcti.algashop.authorization_server.infrastructure.security.check.SecurityAnnotations;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

	private final AuthUserManagementApplicationService managementService;
	private final AuthUserQueryService queryService;

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	@SecurityAnnotations.CanWriteUsers
	public AuthUserOutput create(@RequestBody @Valid AuthUserInput input) {
		return managementService.create(input);
	}

	@SecurityAnnotations.CanReadUsers
	@GetMapping
	public PageModel<AuthUserOutput> findAll(AuthUserFilter filter) {
		return queryService.findAll(filter);
	}

	@SecurityAnnotations.CanReadUsers
	@GetMapping("/{userId}")
	public AuthUserOutput findById(@PathVariable UUID userId) {
		return queryService.findById(userId);
	}

	@SecurityAnnotations.CanWriteUsers
	@PutMapping("/{userId}")
	public AuthUserOutput update(@PathVariable UUID userId, @RequestBody @Valid AuthUserUpdateInput input) {
		return managementService.update(userId, input);
	}

	@SecurityAnnotations.CanWriteUsers
	@DeleteMapping("/{userId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void delete(@PathVariable UUID userId) {
		managementService.delete(userId);
	}

}
