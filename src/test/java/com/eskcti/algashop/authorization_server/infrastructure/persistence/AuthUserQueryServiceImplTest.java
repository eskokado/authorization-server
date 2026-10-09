package com.eskcti.algashop.authorization_server.infrastructure.persistence;

import com.eskcti.algashop.authorization_server.application.user.query.AuthUserFilter;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserNotFoundException;
import com.eskcti.algashop.authorization_server.application.user.query.AuthUserOutput;
import com.eskcti.algashop.authorization_server.application.user.query.PageModel;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUser;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserRepository;
import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CompoundSelection;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"unchecked", "rawtypes"})
class AuthUserQueryServiceImplTest {

	@Mock
	private AuthUserRepository authUserRepository;

	@Mock
	private EntityManager entityManager;

	@Mock
	private CriteriaBuilder criteriaBuilder;

	@Mock
	private Root<AuthUser> root;

	private CriteriaQuery<Long> countCriteriaQuery;
	private CriteriaQuery<AuthUserOutput> dataCriteriaQuery;
	private TypedQuery typedQuery;

	private AuthUserQueryServiceImpl service;

	@BeforeEach
	void setUp() {
		service = new AuthUserQueryServiceImpl(authUserRepository, entityManager);
		countCriteriaQuery = mock(CriteriaQuery.class);
		dataCriteriaQuery = mock(CriteriaQuery.class);
		typedQuery = mock(TypedQuery.class);

		when(entityManager.getCriteriaBuilder()).thenReturn(criteriaBuilder);
		when(criteriaBuilder.createQuery(Long.class)).thenReturn(countCriteriaQuery);
		when(criteriaBuilder.createQuery(AuthUserOutput.class)).thenReturn(dataCriteriaQuery);
		when(entityManager.createQuery(any(CriteriaQuery.class))).thenReturn(typedQuery);
		when(root.get(anyString())).thenReturn(mock(Path.class));

		when(countCriteriaQuery.from(AuthUser.class)).thenReturn(root);
		when(countCriteriaQuery.select(any())).thenReturn(countCriteriaQuery);
		when(countCriteriaQuery.where(any(Predicate[].class))).thenReturn(countCriteriaQuery);

		when(dataCriteriaQuery.from(AuthUser.class)).thenReturn(root);
		when(dataCriteriaQuery.select(any())).thenReturn(dataCriteriaQuery);
		when(dataCriteriaQuery.where(any(Predicate[].class))).thenReturn(dataCriteriaQuery);
		when(dataCriteriaQuery.orderBy(any(Order.class))).thenReturn(dataCriteriaQuery);
	}

	@Test
	void findById_returnsMappedOutput() {
		UUID userId = UUID.randomUUID();
		AuthUser user = AuthUser.brandNew("alice@algashop.com", "Alice", AuthUserType.MANAGER, "hash");
		when(authUserRepository.findById(userId)).thenReturn(Optional.of(user));

		AuthUserOutput output = service.findById(userId);

		assertThat(output.getId()).isEqualTo(user.getId());
		assertThat(output.getEmail()).isEqualTo("alice@algashop.com");
		assertThat(output.getName()).isEqualTo("Alice");
		assertThat(output.getType()).isEqualTo(AuthUserType.MANAGER);
		assertThat(output.isEnabled()).isTrue();
	}

	@Test
	void findById_throwsWhenUserDoesNotExist() {
		UUID userId = UUID.randomUUID();
		when(authUserRepository.findById(userId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.findById(userId))
				.isInstanceOf(AuthUserNotFoundException.class)
				.hasMessageContaining(userId.toString());
	}

	@Test
	void findAll_returnsEmptyPageWhenNoMatch() {
		stubCount(0L);

		PageModel<AuthUserOutput> page = service.findAll(new AuthUserFilter());

		assertThat(page.getContent()).isEmpty();
		assertThat(page.getTotalElements()).isZero();
		assertThat(page.getTotalPages()).isZero();
		assertThat(page.getSize()).isEqualTo(15);
	}

	@Test
	void findAll_filtersByTypeAscendingByName() {
		AuthUserFilter filter = new AuthUserFilter();
		filter.setType(AuthUserType.MANAGER);
		filter.setDirection(Sort.Direction.ASC);
		stubCount(1L);
		stubPredicates();
		when(criteriaBuilder.asc(any(Path.class))).thenReturn(mock(Order.class));
		stubResultList();

		PageModel<AuthUserOutput> page = service.findAll(filter);

		assertThat(page.getContent()).hasSize(1);
		assertThat(page.getTotalElements()).isEqualTo(1L);
		verify(criteriaBuilder).asc(any(Path.class));
		verify(criteriaBuilder, atLeastOnce()).equal(any(Expression.class), eq(AuthUserType.MANAGER));
	}

	@Test
	void findAll_filtersByEmailDescendingWhenRequested() {
		AuthUserFilter filter = new AuthUserFilter();
		filter.setEmail("alice@algashop.com");
		filter.setDirection(Sort.Direction.DESC);
		stubCount(2L);
		stubPredicates();
		when(criteriaBuilder.desc(any(Path.class))).thenReturn(mock(Order.class));
		when(typedQuery.getResultList()).thenReturn(List.of(
				AuthUserOutput.builder().name("Alice").build(),
				AuthUserOutput.builder().name("Bob").build()));

		PageModel<AuthUserOutput> page = service.findAll(filter);

		assertThat(page.getContent()).hasSize(2);
		assertThat(page.getTotalElements()).isEqualTo(2L);
		verify(criteriaBuilder, atLeastOnce()).lower(any(Expression.class));
		verify(criteriaBuilder, atLeastOnce()).like(any(Expression.class), eq("%alice@algashop.com%"));
		verify(criteriaBuilder).desc(any(Path.class));
	}

	private void stubCount(long total) {
		when(typedQuery.getSingleResult()).thenReturn(total);
	}

	private void stubPredicates() {
		when(criteriaBuilder.count(any(Root.class))).thenReturn(mock(Expression.class));
		when(criteriaBuilder.like(any(Expression.class), anyString())).thenReturn(mock(Predicate.class));
		when(criteriaBuilder.equal(any(Expression.class), any())).thenReturn(mock(Predicate.class));
		when(criteriaBuilder.lower(any(Expression.class))).thenReturn(mock(Expression.class));
		when(criteriaBuilder.construct(eq(AuthUserOutput.class), any(Expression[].class)))
				.thenReturn(mock(CompoundSelection.class));
	}

	private void stubResultList() {
		when(typedQuery.getResultList())
				.thenReturn(List.of(AuthUserOutput.builder().name("Alice").build()));
	}
}
