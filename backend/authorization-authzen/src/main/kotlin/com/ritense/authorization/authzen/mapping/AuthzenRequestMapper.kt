/*
 * Copyright 2015-2026 Ritense BV, the Netherlands.
 *
 * Licensed under EUPL, Version 1.2 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ritense.authorization.authzen.mapping

import com.ritense.authorization.Action
import com.ritense.authorization.authzen.client.dto.AuthzenAction
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationRequest
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.request.AuthorizationResourceContext
import com.ritense.authorization.request.EntityAuthorizationRequest
import com.ritense.authorization.request.RelatedEntityAuthorizationRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

/** Raised when a request cannot be expressed as an AuthZEN evaluation. Always denies. */
class AuthzenMappingException(message: String) : RuntimeException(message)

/**
 * Turns a Valtimo [AuthorizationRequest] into one AuthZEN evaluation per entity.
 *
 * A request carrying N entities becomes N evaluations, because PBAC requires **every** entity to be
 * permitted (`AuthorizationSpecification.kt:61`). The caller ANDs the decisions.
 */
class AuthzenRequestMapper(
    private val subjectFactory: AuthzenSubjectFactory,
    resourceProperties: List<AuthzenResourceProperties<*>>,
) {
    private val projectors: Map<String, AuthzenResourceProperties<*>> =
        resourceProperties.associateBy { it.resourceType.name }

    fun map(resourceType: Class<*>, action: Action<*>): List<AuthzenEvaluationRequest> {
        if (action.key == Action.DENY) {
            return emptyList()
        }

        val subject = subjectFactory.currentUserSubject()
            ?: throw AuthzenMappingException("Could not establish a subject for ${resourceType.name}")

        val action = AuthzenAction(name = action.key)

        return listOf(
                AuthzenEvaluationRequest(
                    subject = subject,
                    resource = AuthzenResource(type = resourceType.name, id = ANY_RESOURCE_ID),
                    action = action,
                    context = contextOf(resourceType),
                )
            )
    }

    fun map(request: AuthorizationRequest<*>): List<AuthzenEvaluationRequest> {
        val resourceType = request.resourceType.name

        if (request.action.key == Action.DENY) {
            return emptyList()
        }

        val subject = subjectFactory.subjectFor(request)
            ?: throw AuthzenMappingException("Could not establish a subject for ${describe(request)}")

        val action = AuthzenAction(name = request.action.key)

        return when (request) {
            is RelatedEntityAuthorizationRequest -> listOf(
                AuthzenEvaluationRequest(
                    subject = subject,
                    resource = AuthzenResource(type = resourceType, id = ANY_RESOURCE_ID),
                    action = action,
                    context = contextOf(request.context, relatedOf(request)),
                )
            )

            is EntityAuthorizationRequest ->
                entityEvaluations(request, resourceType, subject, action)

            else -> throw AuthzenMappingException(
                "Unsupported authorization request type '${request::class.qualifiedName}'. " +
                    "Denying rather than guessing at its meaning."
            )
        }
    }

    private fun entityEvaluations(
        request: EntityAuthorizationRequest<*>,
        resourceType: String,
        subject: AuthzenSubject,
        action: AuthzenAction,
    ): List<AuthzenEvaluationRequest> {
        val context = contextOf(request.context, null)

        if (request.entities.isEmpty()) {
            return listOf(
                AuthzenEvaluationRequest(
                    subject = subject,
                    resource = AuthzenResource(type = resourceType, id = ANY_RESOURCE_ID),
                    action = action,
                    context = context,
                )
            )
        }

        return request.entities.map { entity ->
            AuthzenEvaluationRequest(
                subject = subject,
                resource = resourceOf(resourceType, entity),
                action = action,
                context = context,
            )
        }
    }

    private fun resourceOf(logicalType: String, entity: Any?): AuthzenResource {
        if (entity == null) return AuthzenResource(type = logicalType, id = ANY_RESOURCE_ID)

        return AuthzenResource(
            type = logicalType,
            id = getIdAsString(entity)
        )
    }

    private fun getIdAsString(entity: Any): String {
        return entity::class.memberProperties.
            firstOrNull { it.name == "id" }
            ?.getter
            ?.apply {
                isAccessible = true
            }
            ?.call(entity)
            ?.toString() ?: "*"
    }

    /**
     * The enclosing resource, when the request carries one. PBAC calls this the
     * [AuthorizationResourceContext]; a policy sees it as `context.resource`.
     */
    private fun contextOf(
        resourceContext: AuthorizationResourceContext<*>?,
        related: Map<String, Any?>?,
    ): Map<String, Any?>? {
        val context = buildMap<String, Any?> {
            resourceContext?.let { ctx ->
                val logicalType = ctx.resourceType.name
                if (logicalType == null) {
                    // Not fatal: the context narrows a decision, and a policy that needs it will
                    // deny on its absence. Denying here instead would break every request that
                    // merely happens to carry a context.
                    logger.debug {
                        "Authorization context type '${ctx.resourceType.name}' has no AuthZEN mapping; " +
                            "omitting it from the request."
                    }
                } else {
                    // AuthorizationResourceContext<*> hands back a captured type; the projector
                    // lookup is by runtime class, so widen it here.
                    val contextEntity: Any? = ctx.entity
                    val projector = projectorFor(contextEntity)
                    put(
                        CONTEXT_RESOURCE,
                        mapOf(
                            "type" to logicalType,
                            "id" to (contextEntity?.let { projector?.idOf(it) } ?: ANY_RESOURCE_ID),
                            "properties" to (contextEntity?.let { projector?.propertiesOf(it) } ?: emptyMap()),
                        )
                    )
                }
            }
            related?.let { put(CONTEXT_RELATED, it) }
        }
        return context.ifEmpty { null }
    }

    private fun contextOf(
        resourceType: Class<*>,
    ): Map<String, Any?>? {
        val context = buildMap<String, Any?> {
            put(
                CONTEXT_RESOURCE,
                mapOf(
                    "type" to resourceType.name,
                    "id" to "*",
                )
            )
        }
        return context.ifEmpty { null }
    }

    private fun relatedOf(request: RelatedEntityAuthorizationRequest<*>): Map<String, Any?>? {
        val logicalType = request.resourceType.name
        if (logicalType == null) {
            logger.debug {
                "Related resource type '${request.relatedResourceType.name}' has no AuthZEN mapping; " +
                    "omitting it from the request."
            }
            return null
        }
        return mapOf("type" to logicalType, "id" to request.relatedResourceId)
    }

    @Suppress("UNCHECKED_CAST")
    private fun projectorFor(entity: Any?): AuthzenResourceProperties<Any>? {
        if (entity == null) return null
        // Exact class first, then an assignable projector — entities are routinely proxied or
        // subclassed, and a projector registered for the domain type should still claim them.
        return (projectors[entity.javaClass.name]
            ?: projectors.values.firstOrNull { it.resourceType.isInstance(entity) })
            as AuthzenResourceProperties<Any>?
    }

    private fun describe(request: AuthorizationRequest<*>) =
        "'${request.action.key}:${request.resourceType.simpleName}'"

    companion object {
        private val logger = KotlinLogging.logger {}

        /**
         * Sent as `resource.id` when a request is not about one specific instance.
         *
         * The PDP rejects an evaluation whose resource has no id with `400 invalid resource`, and
         * plenty of Valtimo requests legitimately have no instance — "may I create one at all?", or
         * a marker resource type with no identity. **Policies must not read `resource.id` as proof
         * that a specific entity exists.**
         */
        const val ANY_RESOURCE_ID = "*"

        const val CONTEXT_RESOURCE = "resource"
        const val CONTEXT_RELATED = "related"
    }
}
