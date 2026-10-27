package com.eskcti.algashop.authorization_server.application.user.mail;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;

public interface AuthUserMailSender {
	void sendActivationEmail(AuthUser user, String token);

	void sendPasswordChangeEmail(AuthUser user, String token);
}
