package com.eskcti.algashop.authorization_server.support;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserPasswordManager;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;

public final class AuthUserFixtures {

	public static final String ENCRYPTED_PASSWORD = "hash";

	private static final AuthUserPasswordManager PASSWORD_MANAGER = new AuthUserPasswordManager() {
		@Override
		public String generates() {
			return "temp-password";
		}

		@Override
		public String encrypt(String plainPassword) {
			return ENCRYPTED_PASSWORD;
		}

		@Override
		public boolean matches(String encryptedPassword, String plainPassword) {
			return false;
		}
	};

	private AuthUserFixtures() {
	}

	public static AuthUser newUser(String email, String name, AuthUserType type) {
		return AuthUser.brandNew(email, name, type, PASSWORD_MANAGER);
	}

	public static AuthUser verified(AuthUser user) {
		setField(user, "emailVerified", true);
		return user;
	}

	private static void setField(AuthUser user, String name, Object value) {
		try {
			var field = AuthUser.class.getDeclaredField(name);
			field.setAccessible(true);
			field.set(user, value);
		} catch (ReflectiveOperationException e) {
			throw new IllegalStateException(e);
		}
	}
}
