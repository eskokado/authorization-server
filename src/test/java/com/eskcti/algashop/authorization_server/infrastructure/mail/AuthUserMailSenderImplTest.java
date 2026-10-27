package com.eskcti.algashop.authorization_server.infrastructure.mail;

import com.eskcti.algashop.authorization_server.application.user.UserAccountProperties;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.Duration;
import java.util.Properties;

import static com.eskcti.algashop.authorization_server.support.AuthUserFixtures.newUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthUserMailSenderImplTest {

	private static final String PASSWORD_CHANGE_URL = "http://auth.algashop.local:8081/change-password";
	private static final String FROM = "AlgaShop <no-reply@algashop.com>";

	@Mock
	private JavaMailSender javaMailSender;

	private UserAccountProperties properties;
	private AuthUserMailSenderImpl mailSender;

	@BeforeEach
	void setUp() {
		properties = new UserAccountProperties();
		UserAccountProperties.PasswordToken token = new UserAccountProperties.PasswordToken();
		token.setActivationTtl(Duration.ofHours(24));
		token.setPasswordResetTtl(Duration.ofHours(2));
		properties.setToken(token);

		UserAccountProperties.Mail mail = new UserAccountProperties.Mail();
		mail.setFrom(FROM);
		mail.setPasswordChangeUrl(PASSWORD_CHANGE_URL);
		properties.setMail(mail);

		mailSender = new AuthUserMailSenderImpl(javaMailSender, properties);
	}

	@Test
	void sendActivationEmail_sendsFormattedMessageInHours() throws Exception {
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.CUSTOMER);
		MimeMessage message = new MimeMessage(Session.getInstance(new Properties()));
		when(javaMailSender.createMimeMessage()).thenReturn(message);

		mailSender.sendActivationEmail(user, "plain-token");

		verify(javaMailSender).send(message);
		assertThat(message.getSubject()).isEqualTo("AlgaShop - Active your account");
		assertThat(message.getFrom()[0].toString()).isEqualTo(FROM);
		assertThat(message.getAllRecipients()[0].toString()).isEqualTo("alice@algashop.com");
		assertThat(message.getContent().toString())
				.contains("Hello Alice")
				.contains(PASSWORD_CHANGE_URL + "?token=plain-token")
				.contains("This link expires in 24 hour(s).");
	}

	@Test
	void sendPasswordChangeEmail_usesMinutesWhenTtlIsBelowOneHour() throws Exception {
		properties.getToken().setActivationTtl(Duration.ofMinutes(30));
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.MANAGER);
		MimeMessage message = new MimeMessage(Session.getInstance(new Properties()));
		when(javaMailSender.createMimeMessage()).thenReturn(message);

		mailSender.sendPasswordChangeEmail(user, "reset-token");

		verify(javaMailSender).send(message);
		assertThat(message.getSubject()).isEqualTo("AlgaShop - Password change");
		assertThat(message.getAllRecipients()[0].toString()).isEqualTo("alice@algashop.com");
		assertThat(message.getContent().toString())
				.contains("Hello Alice")
				.contains(PASSWORD_CHANGE_URL + "?token=reset-token")
				.contains("Use the link bellow to set your password:")
				.contains("This link expires in 30 minute(s).");
	}

	@Test
	void send_doesNotPropagateMailSenderFailure() {
		when(javaMailSender.createMimeMessage()).thenThrow(new MailSendException("smtp unavailable"));
		AuthUser user = newUser("alice@algashop.com", "Alice", AuthUserType.CUSTOMER);

		assertThatCode(() -> mailSender.sendActivationEmail(user, "plain-token"))
				.doesNotThrowAnyException();
		assertThatCode(() -> mailSender.sendPasswordChangeEmail(user, "reset-token"))
				.doesNotThrowAnyException();
	}
}
