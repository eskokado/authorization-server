package com.eskcti.algashop.authorization_server.presentation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationConsentControllerTest {

	private static final String CLIENT_ID = "algashop-ecommerce-web";
	private static final String REGISTERED_CLIENT_ID = "registered-client-uuid";
	private static final String PRINCIPAL_NAME = "alice@algashop.com";

	@Mock
	private RegisteredClientRepository registeredClientRepository;

	@Mock
	private OAuth2AuthorizationConsentService authorizationConsentService;

	@Mock
	private Principal principal;

	@InjectMocks
	private AuthorizationConsentController controller;

	private final Model model = new ExtendedModelMap();

	@Test
	void consent_semConsentPrevio_aprovaTodosOsScopesSolicitados() {
		stubPrincipal();
		stubRegisteredClient();
		when(authorizationConsentService.findById(REGISTERED_CLIENT_ID, PRINCIPAL_NAME))
				.thenReturn(null);

		String view = controller.consent(principal, model, CLIENT_ID,
				"products:read orders:write", "state-1", null);

		assertThat(view).isEqualTo("consent-page");
		assertThat(scopeValues("scopes"))
				.containsExactlyInAnyOrder("products:read", "orders:write");
		assertThat(scopeValues("previouslyApprovedScopes")).isEmpty();
		assertThat(model.getAttribute("clientId")).isEqualTo(CLIENT_ID);
		assertThat(model.getAttribute("state")).isEqualTo("state-1");
		assertThat(model.getAttribute("principalName")).isEqualTo(PRINCIPAL_NAME);
		assertThat(model.getAttribute("userCode")).isNull();
		assertThat(model.getAttribute("requestURI")).isEqualTo("/oauth2/authorize");
	}

	@Test
	void consent_comConsentPrevio_separaScopesJaAprovados() {
		stubPrincipal();
		stubRegisteredClient();
		OAuth2AuthorizationConsent existingConsent = OAuth2AuthorizationConsent
				.withId(REGISTERED_CLIENT_ID, PRINCIPAL_NAME)
				.scope("products:read")
				.build();
		when(authorizationConsentService.findById(REGISTERED_CLIENT_ID, PRINCIPAL_NAME))
				.thenReturn(existingConsent);

		controller.consent(principal, model, CLIENT_ID,
				"products:read orders:write", "state-1", null);

		assertThat(scopeValues("previouslyApprovedScopes")).containsExactly("products:read");
		assertThat(scopeValues("scopes")).containsExactly("orders:write");
	}

	@Test
	void consent_ignoraScopeOpenid() {
		stubPrincipal();
		stubRegisteredClient();
		when(authorizationConsentService.findById(REGISTERED_CLIENT_ID, PRINCIPAL_NAME))
				.thenReturn(null);

		controller.consent(principal, model, CLIENT_ID,
				"openid products:read", "state-1", null);

		assertThat(scopeValues("scopes")).containsExactly("products:read");
		assertThat(scopeValues("previouslyApprovedScopes")).isEmpty();
	}

	@Test
	void consent_comUserCode_usaUriDeVerificacaoDoDispositivo() {
		stubPrincipal();
		stubRegisteredClient();
		when(authorizationConsentService.findById(REGISTERED_CLIENT_ID, PRINCIPAL_NAME))
				.thenReturn(null);

		controller.consent(principal, model, CLIENT_ID,
				"orders:read", "state-1", "device-code");

		assertThat(model.getAttribute("requestURI")).isEqualTo("/oauth2/device_verification");
		assertThat(model.getAttribute("userCode")).isEqualTo("device-code");
	}

	@Test
	void consent_semScopesSolicitados_listasVazias() {
		stubPrincipal();
		stubRegisteredClient();
		when(authorizationConsentService.findById(REGISTERED_CLIENT_ID, PRINCIPAL_NAME))
				.thenReturn(null);

		controller.consent(principal, model, CLIENT_ID, "", "state-1", null);

		assertThat(scopeValues("scopes")).isEmpty();
		assertThat(scopeValues("previouslyApprovedScopes")).isEmpty();
	}

	@Test
	void scopeWithDescription_conheceDescricoesPadraoEDefault() {
		AuthorizationConsentController.ScopeWithDescription known =
				new AuthorizationConsentController.ScopeWithDescription("products:read");
		AuthorizationConsentController.ScopeWithDescription unknown =
				new AuthorizationConsentController.ScopeWithDescription("custom:scope");

		assertThat(known.value).isEqualTo("products:read");
		assertThat(known.description).isEqualTo("Read products.");
		assertThat(unknown.value).isEqualTo("custom:scope");
		assertThat(unknown.description).isEqualTo("UNKNOWN SCOPE.");
	}

	@SuppressWarnings("unchecked")
	private Set<String> scopeValues(String attribute) {
		return ((Set<AuthorizationConsentController.ScopeWithDescription>)
				model.getAttribute(attribute)).stream()
				.map(scope -> scope.value)
				.collect(Collectors.toSet());
	}

	private void stubPrincipal() {
		when(principal.getName()).thenReturn(PRINCIPAL_NAME);
	}

	private void stubRegisteredClient() {
		RegisteredClient registeredClient = RegisteredClient.withId(REGISTERED_CLIENT_ID)
				.clientId(CLIENT_ID)
				.clientName("AlgaShop E-commerce")
				.authorizationGrantType(
						org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("http://localhost:9080/callback")
				.build();
		when(registeredClientRepository.findByClientId(CLIENT_ID))
				.thenReturn(registeredClient);
	}

}
