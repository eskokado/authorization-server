package com.eskcti.algashop.authorization_server.presentation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoginControllerTest {

	private final LoginController controller = new LoginController();

	@Test
	void login_retornaLoginPage() {
		assertThat(controller.login()).isEqualTo("login-page");
	}

}
