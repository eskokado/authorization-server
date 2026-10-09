package com.eskcti.algashop.authorization_server.domain.model;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdGeneratorTest {

	@Test
	void generateTimeBasedUUID_returnsUniqueSortedIds() {
		UUID first = IdGenerator.generateTimeBasedUUID();
		UUID second = IdGenerator.generateTimeBasedUUID();

		assertThat(first).isNotNull();
		assertThat(second).isNotNull();
		assertThat(first).isNotEqualTo(second);
		assertThat(first.version()).isEqualTo(7);
	}

	@Test
	void constructor_isNotAccessible() {
		var constructors = IdGenerator.class.getDeclaredConstructors();

		assertThat(constructors).hasSize(1);
		assertThat(constructors[0].canAccess(null)).isFalse();
	}
}

class DomainExceptionTest {

	@Test
	void constructors_exposeMessageAndCause() {
		assertThat(new DomainException().getMessage()).isNull();
		assertThat(new DomainException("boom").getMessage()).isEqualTo("boom");
		assertThat(new DomainException("boom").getCause()).isNull();
		assertThat(new DomainException(new IllegalStateException("x")).getCause())
				.isInstanceOf(IllegalStateException.class);
		assertThat(new DomainException("boom", new IllegalStateException("x")).getCause())
				.isInstanceOf(IllegalStateException.class);

		var withFlags = new DomainException("boom", new IllegalStateException("x"), true, false);
		assertThat(withFlags.getMessage()).isEqualTo("boom");
		assertThat(withFlags.getCause()).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void domainException_isRuntimeException() {
		assertThat(new DomainException("boom")).isInstanceOf(RuntimeException.class);
		assertThatThrownBy(() -> { throw new DomainException("boom"); })
				.isInstanceOf(DomainException.class)
				.hasMessage("boom");
	}
}
