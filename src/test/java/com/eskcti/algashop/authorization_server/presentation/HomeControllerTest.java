package com.eskcti.algashop.authorization_server.presentation;

import com.eskcti.algashop.authorization_server.infrastructure.security.AlgaShopSecurityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HomeControllerTest {

	@Mock
	private AlgaShopSecurityProperties properties;

	@InjectMocks
	private HomeController controller;

	@Test
	void home_redirecionaParaDefaultRedirectUri() {
		when(properties.getDefaultRedirectUri()).thenReturn("http://algashop.local:9080");

		assertThat(controller.home()).isEqualTo("redirect:http://algashop.local:9080");
	}

}
