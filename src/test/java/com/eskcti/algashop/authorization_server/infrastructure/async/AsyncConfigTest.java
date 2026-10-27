package com.eskcti.algashop.authorization_server.infrastructure.async;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AsyncConfigTest {

	@Test
	void instantiatesConfiguration() {
		assertThat(new AsyncConfig()).isNotNull();
	}
}
