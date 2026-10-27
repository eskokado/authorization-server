package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.application.user.management.PasswordManagementApplicationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.ui.ExtendedModelMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class PublicPasswordControllerTest {

	@Mock
	private PasswordManagementApplicationService passwordManagementService;

	@InjectMocks
	private PublicPasswordController controller;

	@Test
	void passwordForm_returnsInvalidTokenMessageWhenTokenIsMissing() {
		ExtendedModelMap model = new ExtendedModelMap();

		String view = controller.passwordForm(null, model);

		assertThat(view).isEqualTo("password-message");
		assertThat(model.getAttribute("message")).isEqualTo("Invalid token.");
		assertThat(model.getAttribute("success")).isEqualTo(false);
	}

	@Test
	void passwordForm_returnsInvalidTokenMessageWhenTokenIsBlank() {
		ExtendedModelMap model = new ExtendedModelMap();

		String view = controller.passwordForm("   ", model);

		assertThat(view).isEqualTo("password-message");
		assertThat(model.getAttribute("message")).isEqualTo("Invalid token.");
		assertThat(model.getAttribute("success")).isEqualTo(false);
	}

	@Test
	void passwordForm_returnsFormWithTokenWhenTokenIsPresent() {
		ExtendedModelMap model = new ExtendedModelMap();

		String view = controller.passwordForm("plain-token", model);

		assertThat(view).isEqualTo("password-form");
		assertThat(model.getAttribute("token")).isEqualTo("plain-token");
	}

	@Test
	void changePassword_returnsSuccessMessage() {
		ExtendedModelMap model = new ExtendedModelMap();

		String view = controller.changePassword("plain-token", "new-password", model);

		verify(passwordManagementService).changePasswordWithToken("plain-token", "new-password");
		assertThat(view).isEqualTo("password-message");
		assertThat(model.getAttribute("message")).isEqualTo("Password changed successfully.");
		assertThat(model.getAttribute("success")).isEqualTo(true);
	}

	@Test
	void changePassword_returnsInvalidTokenMessageWhenTokenIsRejected() {
		doThrow(new AccessDeniedException("Invalid token"))
				.when(passwordManagementService).changePasswordWithToken("bad-token", "new-password");
		ExtendedModelMap model = new ExtendedModelMap();

		String view = controller.changePassword("bad-token", "new-password", model);

		assertThat(view).isEqualTo("password-message");
		assertThat(model.getAttribute("message")).isEqualTo("Invalid token.");
		assertThat(model.getAttribute("success")).isEqualTo(false);
	}

	@Test
	void forgotPassword_returnsFormView() {
		assertThat(controller.forgotPassword()).isEqualTo("forgot-password");
	}

	@Test
	void forgotPasswordProcessing_requestsPasswordChangeAndReturnsMessageView() {
		String view = controller.forgotPasswordProcessing("alice@algashop.com");

		verify(passwordManagementService).requestPasswordChange("alice@algashop.com");
		assertThat(view).isEqualTo("forgot-password-message");
	}
}
