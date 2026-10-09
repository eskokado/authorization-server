package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.application.security.SecurityCheckApplicationService;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserManagementApplicationService;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserInput;
import com.eskcti.algashop.authorization_server.application.user.management.AuthUserUpdateInput;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserFilter;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserQueryService;
import com.eskcti.algashop.authorization_server.application.user.query.PageModel;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

	@Mock
	private AuthUserManagementApplicationService managementService;

	@Mock
	private AuthUserQueryService queryService;

	@InjectMocks
	private UserController controller;

	@Test
	void create_delegatesToManagementService() {
		AuthUserInput input = AuthUserInput.builder()
				.name("Alice")
				.email("alice@algashop.com")
				.type(AuthUserType.MANAGER)
				.build();
		AuthUserOutput output = AuthUserOutput.builder().name("Alice").build();
		when(managementService.create(input)).thenReturn(output);

		assertThat(controller.create(input)).isSameAs(output);
	}

	@Test
	void findAll_delegatesToQueryService() {
		AuthUserFilter filter = new AuthUserFilter();
		PageModel<AuthUserOutput> page = PageModel.<AuthUserOutput>builder()
				.content(List.of(AuthUserOutput.builder().name("Alice").build()))
				.totalElements(1L)
				.build();
		when(queryService.findAll(filter)).thenReturn(page);

		assertThat(controller.findAll(filter)).isSameAs(page);
	}

	@Test
	void findById_delegatesToQueryService() {
		UUID userId = UUID.randomUUID();
		AuthUserOutput output = AuthUserOutput.builder().id(userId).build();
		when(queryService.findById(userId)).thenReturn(output);

		assertThat(controller.findById(userId)).isSameAs(output);
	}

	@Test
	void update_delegatesToManagementService() {
		UUID userId = UUID.randomUUID();
		AuthUserUpdateInput input = AuthUserUpdateInput.builder()
				.name("Alice Updated")
				.type(AuthUserType.OPERATOR)
				.enabled(true)
				.build();
		AuthUserOutput output = AuthUserOutput.builder().id(userId).name("Alice Updated").build();
		when(managementService.update(userId, input)).thenReturn(output);

		assertThat(controller.update(userId, input)).isSameAs(output);
	}

	@Test
	void delete_delegatesToManagementService() {
		UUID userId = UUID.randomUUID();

		controller.delete(userId);

		verify(managementService).delete(userId);
	}
}

@ExtendWith(MockitoExtension.class)
class MyUserControllerTest {

	@Mock
	private SecurityCheckApplicationService securityCheck;

	@Mock
	private AuthUserQueryService queryService;

	@InjectMocks
	private MyUserController controller;

	@Test
	void getMe_returnsAuthenticatedUserProfile() {
		UUID userId = UUID.randomUUID();
		AuthUserOutput output = AuthUserOutput.builder().id(userId).name("Alice").build();
		when(securityCheck.getAuthenticatedUserId()).thenReturn(userId);
		when(queryService.findById(userId)).thenReturn(output);

		assertThat(controller.getMe()).isSameAs(output);
	}
}
