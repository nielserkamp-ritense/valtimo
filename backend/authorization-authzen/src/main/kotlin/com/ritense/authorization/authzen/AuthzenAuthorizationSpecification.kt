package com.ritense.authorization.authzen

import com.ritense.authorization.permission.Permission
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.specification.AuthorizationSpecification
import jakarta.persistence.criteria.AbstractQuery
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.CriteriaQuery
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root
import org.springframework.data.jpa.domain.Specification

class AuthzenAuthorizationSpecification<T: Any>(
    private val authorizationSpecification: AuthorizationSpecification<T>,
    authRequest: AuthorizationRequest<T>,
                                                permissionSupplier: () -> List<Permission>):
    AuthorizationSpecification<T>(authRequest, permissionSupplier) {

    override fun isAuthorized(): Boolean {
        return authorizationSpecification.isAuthorized()
    }

    override fun identifierToEntity(identifier: String): T {
        return authorizationSpecification.identifierToEntity(identifier)
    }

    override fun toPredicate(
        root: Root<T>,
        query: CriteriaQuery<*>?,
        criteriaBuilder: CriteriaBuilder
    ): Predicate? {
        return authorizationSpecification.toPredicate(root, query, criteriaBuilder)
    }

    override fun toPredicate(
        root: Root<T>,
        query: AbstractQuery<*>,
        criteriaBuilder: CriteriaBuilder
    ): Predicate {
        return authorizationSpecification.toPredicate(root, query, criteriaBuilder)
    }

    override fun and(other: Specification<T?>?): Specification<T?> {
        return authorizationSpecification.and(other)
    }

    override fun or(other: Specification<T?>?): Specification<T?> {
        return authorizationSpecification.or(other)
    }
}