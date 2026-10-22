package com.eskcti.algashop.authorization_server.utils;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Container PostgreSQL compartilhado por toda a JVM de teste.
 *
 * <p>O bean precisa declarar um destroy method que nao pare o container: com
 * {@code destroyMethod = ""} o {@code TestcontainersLifecycleBeanPostProcessor} do Spring Boot
 * chama {@code close()} ao destruir qualquer contexto, e como o mesmo container e exposto em
 * todos os contextos, o primeiro contexto destruido (ex.: {@code @DirtiesContext}) derruba o
 * container e invalida as portas ja entregues aos demais contextos.</p>
 */
@TestConfiguration
public class TestcontainerPostgreSQLConfig {

    private static final SharedPostgreSQLContainer POSTGRESQL_CONTAINER =
            new SharedPostgreSQLContainer("postgres:17-alpine");

    static {
        POSTGRESQL_CONTAINER.start();
    }

    @Bean(destroyMethod = "keepAlive")
    @ServiceConnection
    public PostgreSQLContainer<?> postgreSQLContainer() {
        if (!POSTGRESQL_CONTAINER.isRunning()) {
            POSTGRESQL_CONTAINER.start();
        }
        return POSTGRESQL_CONTAINER;
    }

    public static final class SharedPostgreSQLContainer
            extends PostgreSQLContainer<SharedPostgreSQLContainer> {

        SharedPostgreSQLContainer(String dockerImageName) {
            super(dockerImageName);
        }

        public void keepAlive() {
            // intencionalmente vazio: o container e compartilhado por todos os contextos
            // da JVM de teste e so deve ser encerrado junto com ela (Ryuk).
        }

    }

}
