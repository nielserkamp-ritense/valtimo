package com.ritense.authorization.authzen

import com.ritense.authorization.permission.Permission
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.specification.AuthorizationSpecification
import jakarta.persistence.criteria.AbstractQuery
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root

class AuthzenAuthorizationSpecification<T: Any>(
    private val decision: Boolean,
    private val authorizationSpecification: AuthorizationSpecification<T>,
    authRequest: AuthorizationRequest<T>,
                                                permissionSupplier: () -> List<Permission>):
    AuthorizationSpecification<T>(authRequest, permissionSupplier) {

    override fun isAuthorized(): Boolean {
        return decision && authorizationSpecification.isAuthorized()
    }

    override fun identifierToEntity(identifier: String): T {
        return authorizationSpecification.identifierToEntity(identifier)
    }

    /**
     * A PDP deny filters out every row; otherwise the PDP-published permissions filter the query.
     * The `CriteriaQuery` overload and `and`/`or` are inherited, so they all route through here.
     */
    override fun toPredicate(
        root: Root<T>,
        query: AbstractQuery<*>,
        criteriaBuilder: CriteriaBuilder
    ): Predicate {
        return if (decision) authorizationSpecification.toPredicate(root, query, criteriaBuilder)
        else criteriaBuilder.disjunction()
    }
}
