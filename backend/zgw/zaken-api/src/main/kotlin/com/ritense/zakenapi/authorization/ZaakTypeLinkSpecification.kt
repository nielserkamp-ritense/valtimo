package com.ritense.zakenapi.authorization

import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.permission.Permission
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.specification.AuthorizationSpecification
import com.ritense.valtimo.contract.database.QueryDialectHelper
import com.ritense.zakenapi.domain.ZaakTypeLink
import com.ritense.zakenapi.domain.ZaakTypeLinkId
import com.ritense.zakenapi.repository.ZaakTypeLinkRepository
import jakarta.persistence.criteria.AbstractQuery
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root
import java.util.UUID

class ZaakTypeLinkSpecification(
    authRequest: AuthorizationRequest<ZaakTypeLink>,
    private val zaakTypeLinkRepository: ZaakTypeLinkRepository,
    permissions: List<Permission>,
    private val queryDialectHelper: QueryDialectHelper
) : AuthorizationSpecification<ZaakTypeLink>(authRequest, { permissions }) {
    override fun identifierToEntity(identifier: String): ZaakTypeLink {
        return runWithoutAuthorization {
            zaakTypeLinkRepository.findById(ZaakTypeLinkId.existingId(UUID.fromString(identifier))).orElseThrow { NoSuchElementException(identifier) }
        }
    }

    override fun toPredicate(
        root: Root<ZaakTypeLink>,
        query: AbstractQuery<*>,
        criteriaBuilder: CriteriaBuilder
    ): Predicate {
        val predicates = permissions
            .filter { permission ->
                ZaakTypeLink::class.java == permission.resourceType
                    && permission.actions.contains(authRequest.action)
            }
            .map { permission ->
                permission.toPredicate(
                    root,
                    query,
                    criteriaBuilder,
                    authRequest,
                    queryDialectHelper
                )
            }
        return combinePredicates(criteriaBuilder, predicates)
    }
}