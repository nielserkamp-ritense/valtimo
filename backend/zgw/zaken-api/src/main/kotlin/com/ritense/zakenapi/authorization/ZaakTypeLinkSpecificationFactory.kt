package com.ritense.zakenapi.authorization

import com.ritense.authorization.permission.Permission
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.specification.AuthorizationSpecification
import com.ritense.authorization.specification.AuthorizationSpecificationFactory
import com.ritense.valtimo.contract.database.QueryDialectHelper
import com.ritense.zakenapi.domain.ZaakTypeLink
import com.ritense.zakenapi.repository.ZaakTypeLinkRepository

class ZaakTypeLinkSpecificationFactory(
    private var zaakTypeLinkRepository: ZaakTypeLinkRepository,
    private var queryDialectHelper: QueryDialectHelper
) : AuthorizationSpecificationFactory<ZaakTypeLink> {
    override fun create(
        request: AuthorizationRequest<ZaakTypeLink>,
        permissions: List<Permission>
    ): AuthorizationSpecification<ZaakTypeLink> {
        return ZaakTypeLinkSpecification(
            request,
            zaakTypeLinkRepository,
            permissions,
            queryDialectHelper
        )
    }

    override fun canCreate(
        request: AuthorizationRequest<*>,
        permissions: List<Permission>
    ): Boolean {
        return ZaakTypeLink::class.java == request.resourceType
    }
}
