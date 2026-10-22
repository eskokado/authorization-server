package com.eskcti.algashop.authorization_server.presentation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LogoutControllerTest {

	private final LogoutController controller = new LogoutController();

	@Test
	void logout_retornaLogoutPage() {
		assertThat(controller.logout()).isEqualTo("logout-page");
	}

}
