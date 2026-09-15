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
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenSearchSubject
import com.ritense.authorization.authzen.client.dto.AuthzenSubjectSearchRequest
import com.ritense.authorization.authzen.mapping.AuthzenRequestMapper
import com.ritense.authorization.permission.ConditionContainer
import com.ritense.authorization.permission.Permission
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
import kotlin.collections.joinToString

@Service
@SkipComponentScan
class AuthzenAuthorizationService(
    private val authorizationSpecificationFactories: List<AuthorizationSpecificationFactory<*>>,
    private val mappers: List<AuthorizationEntityMapper<*, *>>,
    private val client: AuthzenPdpClient,
    private val requestMapper: AuthzenRequestMapper,
    private val actionProviders: List<ResourceActionProvider<*>>,
    private val userManagementService: UserManagementService,
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
     * The [permissions] argument is a PBAC caching optimisation — the caller pre-fetched permission
     * rows to avoid a per-row database read. A PDP holds its own policy, so the argument has no
     * meaning and is ignored; the request is answered as an ordinary point check.
     *
     * One production call site: `ZaakDocumentService.kt:388`, looping over ZGW documents. That is a
     * pure point-check loop over a resource type with no query filtering, so it works fully here.
     */
    override fun <T : Any> hasPermission(
        request: AuthorizationRequest<T>,
        permissions: List<Permission>,
    ): Boolean = hasPermission(request)

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
        val usedPermissions = { permissions ?: run { getPermissions(request) } }

        return getAuthorizationSpecification(request, usedPermissions, enablePermissionLogging = true)
    }

    override fun <T : Any> getAuthorizedRoles(request: AuthorizationRequest<T>): Set<Role> {
        return getPermissions(request.resourceType, request.action)
            .groupBy { it.role }
            .filter { getAuthorizationSpecification(request, { it.value }, enablePermissionLogging = false).isAuthorized() }
            .map { it.key }
            .toSet()
    }

    override fun getPermissions(resourceType: Class<*>, action: Action<*>): List<Permission> = client.evaluateAllWithResponseType(
            requestMapper.map(resourceType, action),
            AuthzenPermissionContext::class.java,
        ).flatMap { decision ->
            decision.context?.filter.orEmpty().map { filter -> mapToPermission(filter) }
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

    private fun getPermissions(context: AuthorizationRequest<*>): List<Permission> {
        val userRoles = if (context.user == null) {
            SecurityUtils.getCurrentUserRoles()
        } else {
            runWithoutAuthorization { userManagementService.findByUsername(context.user) }
                ?.roles
                ?: return emptyList()
        }

        return getPermissions(context.resourceType, context.action)
            .filter {
                userRoles.contains(it.role.key)
            }
           .filter { permission ->
                context.resourceType == permission.resourceType
                    && permission.actions.contains(context.action)
                    && if (context is EntityAuthorizationRequest) {
                    permission.appliesInContext(context.context?.resourceType, context.context?.entity)
                } else if (context is RelatedEntityAuthorizationRequest)
                {
                    permission.appliesInContext(context.context?.resourceType, context.context?.entity)
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

    private fun mapToPermission(map: AuthzenPermission): Permission {
        return Permission(
            id = UUID.randomUUID(),
            resourceType = Class.forName(map.resourceType),
            actions = map.actions.map { Action<Any>(it) }.toMutableList(),
            role = Role(id = UUID.randomUUID(), key =  map.role),
            conditionContainer = map.conditionContainer,
            contextResourceType = null,
            contextConditionContainer = null,
        )
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

    companion object {
        private val logger = KotlinLogging.logger {}
    }
}
