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

package com.ritense.authorization.authzen

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.ritense.authorization.Action
import com.ritense.authorization.AuthorizationContext
import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.AuthorizationEntityMapper
import com.ritense.authorization.AuthorizationService
import com.ritense.authorization.ResourceActionProvider
import com.ritense.authorization.ValtimoAuthorizationService
import com.ritense.authorization.authzen.client.AuthzenPdpClient
import com.ritense.authorization.authzen.client.dto.AuthzenAction
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationRequest
import com.ritense.authorization.authzen.client.AuthzenPdpException
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationResponseTyped
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenSearchSubject
import com.ritense.authorization.authzen.client.dto.AuthzenSubjectSearchRequest
import com.ritense.authorization.authzen.mapping.AuthzenMappingException
import com.ritense.authorization.authzen.mapping.AuthzenRequestMapper
import com.ritense.authorization.permission.ConditionContainer
import com.ritense.authorization.permission.Permission
import com.ritense.authorization.permission.condition.ContainerPermissionCondition
import com.ritense.authorization.permission.condition.FieldPermissionCondition
import com.ritense.authorization.permission.condition.PermissionCondition
import com.ritense.authorization.permission.condition.PermissionConditionOperator
import com.ritense.authorization.permission.condition.PermissionConditionType
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.request.EntityAuthorizationRequest
import com.ritense.authorization.request.RelatedEntityAuthorizationRequest
import com.ritense.authorization.role.Role
import com.ritense.authorization.specification.AuthorizationSpecification
import com.ritense.authorization.specification.AuthorizationSpecificationFactory
import com.ritense.valtimo.contract.annotation.SkipComponentScan
import com.ritense.valtimo.contract.authentication.UserManagementService
import com.ritense.valtimo.contract.utils.SecurityUtils
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.access.AccessDeniedException
import org.springframework.stereotype.Service
import java.lang.reflect.ParameterizedType
import java.util.UUID
import java.util.function.Supplier
import kotlin.collections.filter
import kotlin.collections.joinToString
import kotlin.reflect.typeOf

@Service
@SkipComponentScan
class AuthzenAuthorizationService(
    private val authorizationSpecificationFactories: List<AuthorizationSpecificationFactory<*>>,
    private val mappers: List<AuthorizationEntityMapper<*, *>>,
    private val client: AuthzenPdpClient,
    private val requestMapper: AuthzenRequestMapper,
    private val actionProviders: List<ResourceActionProvider<*>>,
    private val userManagementService: UserManagementService,
    private val objectMapper: ObjectMapper,
) : AuthorizationService {

    override fun <T : Any> requirePermission(request: AuthorizationRequest<T>) {
        if (!hasPermission(request)) {
            if (request.action.key != Action.DENY) {
                logger.debug {
                    "Unauthorized. User is missing permission '${request.action.key}' on '${request.resourceType}'."
                }
            }
            throw AccessDeniedException("Unauthorized")
        }
    }

    override fun <T : Any> hasPermission(request: AuthorizationRequest<T>): Boolean {
        if (AuthorizationContext.ignoreAuthorization) {
            if (request.action.key != Action.DENY) {
                logger.debug {
                    "Ignoring authorization request for '${request.action.key}:${request.resourceType.simpleName}'."
                }
            }
            return true
        }

        return getAuthorizationSpecification(request).isAuthorized()
    }

    /**
     * Decided locally against [permissions], as in `ValtimoAuthorizationService`. The one production
     * caller (`ZaakDocumentService.kt:388`) obtains them from [getPermissions], so they are already
     * the permissions the PDP published.
     */
    override fun <T : Any> hasPermission(
        request: AuthorizationRequest<T>,
        permissions: List<Permission>,
    ): Boolean = getAuthorizationSpecification(request, permissions).isAuthorized()

    /**
     * Unchanged from `ValtimoAuthorizationService`. This reports the action vocabulary a resource
     * type declares, which is static configuration rather than a decision, so it stays local.
     */
    @Suppress("UNCHECKED_CAST")
    override fun <T : Any> getAvailableActionsForResource(clazz: Class<T>): List<Action<T>> {
        return actionProviders
            .filter { (it.javaClass.genericInterfaces[0] as ParameterizedType).actualTypeArguments[0] == clazz }
            .map { it as ResourceActionProvider<T> }
            .map { it.getAvailableActions() }
            .flatten()
    }

    override fun <T : Any> getAuthorizationSpecification(
        request: AuthorizationRequest<T>,
        permissions: List<Permission>?,
    ): AuthorizationSpecification<T>  {
        // Caller-supplied permissions come from PBAC's own nested evaluation (container conditions,
        // related entities); the bypass and the IGNORE/DENY sentinels are handled by the Noop and
        // Deny factories. None of these is a decision for the PDP.
        if (permissions != null
            || AuthorizationContext.ignoreAuthorization
            || request.action.key == Action.IGNORE
            || request.action.key == Action.DENY
        ) {
            return getAuthorizationSpecification(request, { permissions ?: emptyList() }, enablePermissionLogging = true)
        }

        val evaluations = evaluate { requestMapper.map(request) }

        val usedPermissions = lazySupplier { getPermission(request, evaluations) }

        // Every entity must be permitted, as in `AuthorizationSpecification.isAuthorizedForEntity`.
        val decision = evaluations.isNotEmpty() && evaluations.all { it.decision }

        return AuthzenAuthorizationSpecification(decision, getAuthorizationSpecification(request,
            usedPermissions, enablePermissionLogging = true), request, usedPermissions)
    }

    override fun <T : Any> getAuthorizedRoles(request: AuthorizationRequest<T>): Set<Role> {
        return getPermissions(request.resourceType, request.action)
            .groupBy { it.role }
            .filter { getAuthorizationSpecification(request, { it.value }, enablePermissionLogging = false).isAuthorized() }
            .map { it.key }
            .toSet()
    }

    override fun getPermissions(resourceType: Class<*>, action: Action<*>): List<Permission> =
        evaluate { requestMapper.map(resourceType, action) }.flatMap { decision ->
            decision.context?.get("filter")?.flatMap { filter -> mapToPermissions(resourceType, action, filter) } ?: emptyList()
        }

    override fun <FROM, TO> getMapper(
        from: Class<FROM>,
        to: Class<TO>
    ): AuthorizationEntityMapper<FROM, TO> {
        return (mappers.firstOrNull {
            it.supports(from, to)
        } as AuthorizationEntityMapper<FROM, TO>?)
            ?: throw AccessDeniedException("No entity mapper found for given arguments.")
    }

    override fun hasMapper(from: Class<*>, to: Class<*>): Boolean {
        return mappers.any { it.supports(from, to) }
    }

    /** A PDP or mapping failure denies, as an empty permission list does in `ValtimoAuthorizationService`. */
    private fun evaluate(requests: () -> List<AuthzenEvaluationRequest>): List<AuthzenEvaluationResponseTyped<ObjectNode>> {
        return try {
            client.evaluateAllWithResponseType(requests(), ObjectNode::class.java)
        } catch (e: AuthzenPdpException) {
            logger.warn(e) { "AuthZEN PDP could not be consulted; denying." }
            emptyList()
        } catch (e: AuthzenMappingException) {
            logger.warn(e) { "Authorization request could not be mapped to AuthZEN; denying." }
            emptyList()
        }
    }

    private fun <T> getPermission(request: AuthorizationRequest<T>, evaluations:  List<AuthzenEvaluationResponseTyped<ObjectNode>>): List<Permission> {
        val userRoles = if (request.user == null) {
            SecurityUtils.getCurrentUserRoles()
        } else {
            runWithoutAuthorization { userManagementService.findByUsername(request.user) }
                ?.roles
                ?: return emptyList()
        }

        return evaluations.flatMap { decision ->
            decision.context?.get("filter")?.flatMap { filter -> mapToPermissions(request.resourceType, request.action, filter) } ?: emptyList()
        }.filter {
            userRoles.contains(it.role.key)
        }.filter { permission ->
            request.resourceType == permission.resourceType
                && permission.actions.contains(request.action)
                && if (request is EntityAuthorizationRequest) {
                permission.appliesInContext(request.context?.resourceType, request.context?.entity)
            } else if (request is RelatedEntityAuthorizationRequest)
            {
                permission.appliesInContext(request.context?.resourceType, request.context?.entity)
            } else {
                val requestContextResourceType: Class<*>? = null
                permission.appliesInContext(requestContextResourceType, null)
            }
        }
    }

    /**
     * `filter` defaults to empty and unknown properties are ignored because the response context is
     * never only ours: the PDP publishes `id` and `reason_user` beside it, and a policy that
     * publishes no `filter` at all omits the key entirely rather than sending `[]`.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    data class AuthzenPermissionContext(
        val filter: List<AuthzenPermission> = emptyList()
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    data class AuthzenPermission(
        val resourceType: String,
        val actions: List<String>,
        val conditionContainer: ConditionContainer,
        val role: String,
        val contextResourceType: String? = null,
        val contextConditionContainer: ConditionContainer? = null,
    )

    private fun mapToPermissions(resourceType: Class<*>, action: Action<*>, node: JsonNode): List<Permission> {
        if (node.has("type") && node.get("type").asText() == "ValtimoAuthorizationPermission") {
            val permission = objectMapper.convertValue(node, AuthzenPermission::class.java)

            return listOf(Permission(
                id = UUID.randomUUID(),
                resourceType = Class.forName(permission.resourceType),
                actions = permission.actions.map { Action<Any>(it) }.toMutableList(),
                role = Role(id = UUID.randomUUID(), key =  permission.role),
                conditionContainer = permission.conditionContainer,
                contextResourceType = permission.contextResourceType?.let { Class.forName(it) },
                contextConditionContainer = permission.contextConditionContainer,
            ))
        } else if (node.has("type") && node.get("type").asText() == "ZaakTypePermission") {
            return when (resourceType.name) {
                "com.ritense.case_.domain.definition.CaseDefinition",
                    "com.ritense.document.domain.impl.JsonSchemaDocument" -> node.get("urls")
                    .mapIndexed { _, nodes -> nodes.asText() }
                    .windowed(50, 50, true)
                    .map { urls -> Permission(
                        id = UUID.randomUUID(),
                        resourceType = resourceType,
                        actions = mutableListOf(action),
                        role = Role(id = UUID.randomUUID(), key = node.get("role").asText()),
                        conditionContainer = ConditionContainer(listOf(
                            ContainerPermissionCondition(
                                resourceType = Class.forName("com.ritense.zakenapi.domain.ZaakTypeLink"),
                                conditions = listOf(
                                    FieldPermissionCondition(
                                        field = "zaakTypeUrl",
                                        operator = PermissionConditionOperator.IN,
                                        value = urls
                                    )
                                )
                            )
                        )))
                    } else -> {
                        logger.warn { "ZaakTypePermission does not apply to $resourceType; ignoring it." }
                        emptyList()
                    }
            }

        } else {
            logger.warn { "Unknown permission in PDP filter, ignoring it: $node" }
            return emptyList()
        }
    }

    private fun <T : Any> getAuthorizationSpecification(
        request: AuthorizationRequest<T>,
        permissionSupplier: () -> List<Permission>,
        enablePermissionLogging: Boolean
    ): AuthorizationSpecification<T> {
        if (enablePermissionLogging) {
            logPermissions(request, permissionSupplier)
        }

        val factory = (authorizationSpecificationFactories.firstOrNull {
            it.canCreate(request, permissionSupplier)
        } as AuthorizationSpecificationFactory<T>?)
            ?: throw AccessDeniedException("Missing AuthorizationSpecificationFactory<${request.resourceType.name}>")

        return factory.create(request, permissionSupplier)
    }

    private fun logPermissions(request: AuthorizationRequest<*>, permissionSupplier: Supplier<List<Permission>>) {
        val forUserLogLine = if (request.user.isNullOrEmpty()) "" else " for user '${request.user}'"
        if (!AuthorizationContext.ignoreAuthorization) {
            if (request.action.key == Action.DENY) {
                logger.error {
                    "Access denied on '${request.resourceType}'. This generally indicates attempting to " +
                        "access a resource without considering authorization. Please refer to the Valtimo documentation."
                }
            } else {
                val permissionsLogLine = permissionSupplier.get().joinToString(", ") { "${it.id}:${it.role.key}" }
                val logLine =
                    "Requesting permissions '${request.action.key}:${request.resourceType.simpleName}'$forUserLogLine and found matching permissions: [$permissionsLogLine]"
                logger.debug { logLine }
            }
        } else {
            if (request.action.key != Action.DENY) {
                val logLine =
                    "Ignoring authorization request for '${request.action.key}:${request.resourceType.simpleName}'$forUserLogLine. "
                logger.debug { logLine }
            }
        }
    }

    private fun <T> lazySupplier(delegate: () -> T) = object : () -> T {
        private val value by lazy(delegate)

        override fun invoke() = value
    }

    companion object {
        private val logger = KotlinLogging.logger {}
    }
}
