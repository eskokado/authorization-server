package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.application.user.management.AuthUserInput;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserManagementApplicationService;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

	private final AuthUserManagementApplicationService managementService;

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public AuthUserOutput create(@RequestBody @Valid AuthUserInput input) {
		return managementService.create(input);
	}

}
