package com.eskcti.algashop.authorization_server;

import com.eskcti.algashop.authorization_server.utils.TestcontainerPostgreSQLConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestcontainerPostgreSQLConfig.class)
class AuthorizationServerApplicationTests {

	@Test
	void contextLoads() {
	}

}
