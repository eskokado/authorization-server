package com.eskcti.algashop.authorization_server.infrastructure.security.cors;

import com.eskcti.algashop.authorization_server.infrastructure.security.AlgaShopSecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {

	@Bean
	public CorsConfigurationSource corsConfigurationSource(AlgaShopSecurityProperties properties) {
		CorsConfiguration cors = new CorsConfiguration();

		cors.setAllowedOrigins(properties.getCors().getAllowedOrigins());
		cors.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		cors.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

		var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", cors);
		return source;
	}

}
