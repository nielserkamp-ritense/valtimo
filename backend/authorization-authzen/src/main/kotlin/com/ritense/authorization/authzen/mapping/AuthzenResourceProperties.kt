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

/**
 * Projects a Valtimo entity into the identifier and attributes a policy may reference.
 *
 * One implementation per managed resource type, registered as a Spring bean. This is the declared
 * contract between Valtimo's domain model and the policy surface: policies may reference exactly
 * what a projection publishes, and nothing else.
 *
 * The PDP cannot fetch attributes itself — its PIP is populated ahead of time from files, bundles
 * and scheduled polls, and has no way to call back into Valtimo during a decision. So everything a
 * policy needs has to travel in the request, and this is what puts it there.
 *
 * **An incomplete projection is a silent wrong answer.** A Cedar condition on an absent attribute is
 * simply false, so a missing field denies rather than errors. Publish every field the policies for
 * this type reference. `PbacRegistryService.getRegistry()` computes the candidate field list per
 * resource type and is a useful cross-check.
 */
interface AuthzenResourceProperties<T : Any> {

    /** The Valtimo resource type this projection covers. */
    val resourceType: Class<T>

    /**
     * The entity's identifier, as the policy will see it in `resource.id`.
     *
     * Null when the entity has no meaningful identity, in which case the request carries
     * [AuthzenRequestMapper.ANY_RESOURCE_ID].
     */
    fun idOf(entity: T): String?

    /** The attributes policies may reference, as `resource.properties`. */
    fun propertiesOf(entity: T): Map<String, Any?>
}
