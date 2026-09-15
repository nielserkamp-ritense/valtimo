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

package com.ritense.gzac.authzen

import com.ritense.authorization.authzen.mapping.AuthzenResourceProperties
import com.ritense.objectenapi.security.Object
import com.ritense.valtimo.contract.authentication.ManageableUser
import com.ritense.valtimo.contract.authentication.User
import com.ritense.zakenapi.security.Zaak
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * Resource property projections for the resource types this application hands to the AuthZEN PDP.
 *
 * These live in the application rather than in the owning modules on purpose: nothing in
 * `zgw/objecten-api`, `zgw/zaken-api` or `keycloak-iam` should gain a dependency on the AuthZEN
 * module while this is a spike.
 *
 * Each projection is the declared contract between a domain type and the policy surface — policies
 * may reference exactly what is published here and nothing else. The Cedar rules that consume them
 * live in `pdp/policies/` at the repository root, each naming the `*.permission.json` it was
 * translated from.
 */
@Configuration
@ConditionalOnProperty(
    prefix = "valtimo.authorization.authzen",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
class AuthzenResourceProjections {

    /**
     * `Object` is a field-less marker class — it carries no identity and no attributes, and exists
     * only to name a resource type in a permission check. Its policies are role-only, so an empty
     * projection is the accurate contract rather than an omission.
     */
    @Bean
    fun objectAuthzenProperties(): AuthzenResourceProperties<Object> =
        object : AuthzenResourceProperties<Object> {
            override val resourceType: Class<Object> = Object::class.java
            override fun idOf(entity: Object): String? = null
            override fun propertiesOf(entity: Object): Map<String, Any?> = emptyMap()
        }

    /**
     * `zaaktype` is the single field the dev permission set conditions on
     * (`zaken.permission.json`, a `field ==` comparison), so it is the single property published.
     */
    @Bean
    fun zaakAuthzenProperties(): AuthzenResourceProperties<Zaak> =
        object : AuthzenResourceProperties<Zaak> {
            override val resourceType: Class<Zaak> = Zaak::class.java
            override fun idOf(entity: Zaak): String? = null
            override fun propertiesOf(entity: Zaak): Map<String, Any?> = mapOf("zaaktype" to entity.zaaktype)
        }

    /**
     * The resource here is a *managed user* — the user being looked at, not the one asking.
     * `user.permission.json` conditions on the resource's own roles with `list_contains`, which is
     * why the Cedar policy reads `resource.roles.contains(...)` and the logical type is
     * `managed_user`: `user` is already taken by the subject entity type.
     */
    @Bean
    fun userAuthzenProperties(): AuthzenResourceProperties<User> =
        object : AuthzenResourceProperties<User> {
            override val resourceType: Class<User> = User::class.java
            override fun idOf(entity: User): String? = (entity as? ManageableUser)?.username
            override fun propertiesOf(entity: User): Map<String, Any?> = mapOf("roles" to entity.roles)
        }
}
