package com.ritense.zakenapi.authorization

import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.AuthorizationEntityMapper
import com.ritense.authorization.AuthorizationEntityMapperResult
import com.ritense.case_.domain.definition.CaseDefinition
import com.ritense.valtimo.contract.annotation.SkipComponentScan
import com.ritense.valtimo.contract.case_.CaseDefinitionId
import com.ritense.zakenapi.domain.ZaakTypeLink
import com.ritense.zakenapi.repository.ZaakTypeLinkRepository
import jakarta.persistence.criteria.AbstractQuery
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.Root
import org.semver4j.Semver
import org.springframework.stereotype.Component
import java.util.UUID

@Component
@SkipComponentScan
class CaseDefinitionZaakTypeLinkMapper(
    private val zaakTypeLinkRepository: ZaakTypeLinkRepository,
) : AuthorizationEntityMapper<CaseDefinition, ZaakTypeLink>  {
    override fun mapRelated(entity: CaseDefinition): List<ZaakTypeLink> {
        return runWithoutAuthorization {
            zaakTypeLinkRepository.findByCaseDefinitionId(entity.id)?.let { listOf(it) } ?: emptyList()
        }
    }

    override fun mapQuery(
        root: Root<CaseDefinition>,
        query: AbstractQuery<*>,
        criteriaBuilder: CriteriaBuilder
    ): AuthorizationEntityMapperResult<ZaakTypeLink> {

        val subquery = query.subquery(Int::class.java)
        val zaakTypeLinkQuery = subquery.from(ZaakTypeLink::class.java)

        subquery.select(criteriaBuilder.literal(1))
            .where(
                criteriaBuilder.equal(
                    root.get<CaseDefinitionId>("id")
                        .get<String>("key")
                    ,
                    zaakTypeLinkQuery.get<CaseDefinitionId>("caseDefinitionId")
                        .get<String>("key")
                ),
                criteriaBuilder.equal(
                    root.get<CaseDefinitionId>("id")
                        .get<Semver>("versionTag")
                    ,
                    zaakTypeLinkQuery.get<CaseDefinitionId>("caseDefinitionId")
                        .get<Semver>("versionTag")
                )
            )

        return AuthorizationEntityMapperResult(
            zaakTypeLinkQuery,
            subquery,
            criteriaBuilder.exists(subquery)
        )
    }

    override fun supports(fromClass: Class<*>, toClass: Class<*>): Boolean {
        println("================= YES 3")
        return fromClass == CaseDefinition::class.java && toClass == ZaakTypeLink::class.java
    }
}