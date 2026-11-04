package com.eskcti.algashop.authorization_server.infrastructure.security.jwk;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@Component
@ConfigurationProperties(prefix = "jwk")
public class JwkProperties {
	@NotBlank
	private String privateKeyId;
	@NotBlank
	private String privateKey;
}
