package com.eskcti.algashop.authorization_server.domain.model.user;

public interface AuthUserPasswordManager {
	String generates();
	String encrypt(String plainPassword);
	boolean matches(String encryptedPassword, String plainPassword);
}
