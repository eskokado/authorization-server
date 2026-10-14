package com.eskcti.algashop.authorization_server.infrastructure.security.token;

import com.eskcti.algashop.authorization_server.infrastructure.security.oidc.OidcUserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final OidcUserInfoService oidcUserInfoService;

	@Override
	public void customize(JwtEncodingContext context) {
		String tokenType = context.getTokenType().getValue();
		AuthorizationGrantType authorizationGrantType = context.getAuthorizationGrantType();
		if (isIdToken(tokenType)) {
			customizeIdToken(context);
		} else if (isAccessToken(tokenType) && isUserDelegatedFlow(authorizationGrantType)) {
			customizeAccessToken(context);
		}
	}

	private boolean isUserDelegatedFlow(AuthorizationGrantType authorizationGrantType) {
		return isAuthCodeFlow(authorizationGrantType)
				|| isRefreshTokenFlow(authorizationGrantType);
	}

	private void customizeAccessToken(JwtEncodingContext context) {
		OidcUserInfo oidcUserInfo = loadUser(context);
		context.getClaims().subject(oidcUserInfo.getSubject());
		context.getClaims().claim("role", oidcUserInfo.getClaimAsString("type"));
	}

	private void customizeIdToken(JwtEncodingContext context) {
		OidcUserInfo oidcUserInfo = loadUser(context);
		context.getClaims().claims(claims -> claims.putAll(oidcUserInfo.getClaims()));
	}

	private boolean isRefreshTokenFlow(AuthorizationGrantType authorizationGrantType) {
		return AuthorizationGrantType.REFRESH_TOKEN.equals(authorizationGrantType);
	}

	private boolean isAuthCodeFlow(AuthorizationGrantType authorizationGrantType) {
		return AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType);
	}

	private OidcUserInfo loadUser(JwtEncodingContext context) {
		String email = context.getPrincipal().getName();
		return oidcUserInfoService.loadUser(email);
	}

	private boolean isAccessToken(String tokenType) {
		return OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType);
	}

	private boolean isIdToken(String tokenType) {
		return OidcParameterNames.ID_TOKEN.equals(tokenType);
	}
}
