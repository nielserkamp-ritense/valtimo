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

import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.authzen.AuthzenProperties
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.valtimo.contract.authentication.UserManagementService
import com.ritense.valtimo.contract.utils.SecurityUtils
import io.github.oshai.kotlinlogging.KotlinLogging

/**
 * Builds the AuthZEN `subject` for an authorization request.
 *
 * The subject properties mirror the six `${currentUser*}` placeholders that
 * `CurrentUserExpressionHandler` resolves for PBAC. In an AuthZEN world these stop being
 * placeholders: the values travel on the request and the policy references them directly, which
 * removes a lookup from the enforcement path.
 */
class AuthzenSubjectFactory(
    private val userManagementService: UserManagementService,
    private val properties: AuthzenProperties,
) {
    /**
     * The subject for [request], or null when no subject can be established.
     *
     * Null is a denial. It mirrors `ValtimoAuthorizationService.getPermissions`, which returns an
     * empty permission list — and therefore denies — when a named user cannot be resolved.
     */
    fun subjectFor(request: AuthorizationRequest<*>): AuthzenSubject? =
        if (request.user == null) currentUserSubject() else delegateUserSubject(request.user!!)

    fun currentUserSubject(): AuthzenSubject? {
        val login = SecurityUtils.getCurrentUserLogin()
        if (login.isNullOrBlank()) {
            logger.debug { "No authenticated user; denying without consulting the PDP." }
            return null
        }

        val subjectProperties = buildMap<String, Any?> {
            put(ROLES, SecurityUtils.getCurrentUserRoles() ?: emptyList<String>())
            // These come from the identity provider and are optional: several UserManagementService
            // implementations throw NotImplementedException rather than answering. A policy that
            // references a property we could not resolve should deny, which is what an absent
            // property does — so a failure here is logged and dropped, never fatal.
            optionally(TEAMS) { userManagementService.currentUserTeams }
            optionally(EMAIL) { userManagementService.currentUser.email }
            optionally(NAME) { userManagementService.currentUser.fullName }
            optionally(USERNAME) { userManagementService.currentUser.username }
        }

        return AuthzenSubject(type = properties.subjectType, id = login, properties = subjectProperties)
    }

    private fun delegateUserSubject(username: String): AuthzenSubject? {
        // Resolving the delegate must not itself be an authorized operation, matching
        // ValtimoAuthorizationService.kt:138.
        val user = runCatching { runWithoutAuthorization { userManagementService.findByUsername(username) } }
            .onFailure { logger.warn(it) { "Failed to resolve delegate user '$username'; denying." } }
            .getOrNull()

        if (user == null) {
            logger.debug { "Delegate user '$username' is unknown; denying without consulting the PDP." }
            return null
        }

        val subjectProperties = buildMap<String, Any?> {
            // The *delegate's* roles, not the caller's.
            put(ROLES, user.roles)
            put(EMAIL, user.email)
            put(NAME, user.fullName)
            put(USERNAME, user.username)
            // Teams are only available for the current user, so a delegate request carries none.
            // A policy using teams must not be applied to a delegate action.
        }

        return AuthzenSubject(type = properties.subjectType, id = username, properties = subjectProperties)
    }

    private inline fun MutableMap<String, Any?>.optionally(key: String, value: () -> Any?) {
        runCatching(value)
            .onFailure { logger.debug { "Subject property '$key' is unavailable: ${it.message}" } }
            .getOrNull()
            ?.let { put(key, it) }
    }

    companion object {
        private val logger = KotlinLogging.logger {}

        const val ROLES = "roles"
        const val TEAMS = "teams"
        const val EMAIL = "email"
        const val NAME = "name"
        const val USERNAME = "username"
    }
}
