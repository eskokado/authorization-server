package com.eskcti.algashop.authorization_server.application.user.management;


public class AuthUserEmailAlreadyInUseException extends RuntimeException {
	public AuthUserEmailAlreadyInUseException(String email) {
		super("Email already in use " + email);
	}
}
