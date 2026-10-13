package com.eskcti.algashop.authorization_server.infrastructure.security.cookie;

import com.eskcti.algashop.authorization_server.infrastructure.security.AlgaShopSecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
public class CookieConfig {

	@Bean
	public CookieSerializer cookieSerializer(AlgaShopSecurityProperties algaShopSecurityProperties) {
		var properties = algaShopSecurityProperties.getCookie();
		DefaultCookieSerializer serializer = new DefaultCookieSerializer();

		serializer.setCookieName("SESSION");
		serializer.setCookiePath("/");
		serializer.setUseHttpOnlyCookie(true);

		serializer.setUseSecureCookie(properties.getSecure());
		serializer.setSameSite(properties.getSameSite());
		serializer.setDomainName(properties.getDomainName());

		return serializer;
	}
}
