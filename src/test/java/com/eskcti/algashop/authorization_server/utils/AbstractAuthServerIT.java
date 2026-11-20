package com.eskcti.algashop.authorization_server.utils;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;

public abstract class AbstractAuthServerIT {

    private static final String PRIVATE_KEY_BASE64 = generatePrivateKeyBase64();

    @DynamicPropertySource
    static void jwkProperties(DynamicPropertyRegistry registry) {
        registry.add("jwk.private-key-id", () -> "test-key");
        registry.add("jwk.private-key", () -> PRIVATE_KEY_BASE64);
    }

    private static String generatePrivateKeyBase64() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            byte[] privateKey = generator.generateKeyPair().getPrivate().getEncoded();
            String pem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey)
                    + "\n-----END PRIVATE KEY-----\n";
            return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
        } catch (Exception exception) {
            throw new IllegalStateException("Could not generate test RSA key", exception);
        }
    }
}
