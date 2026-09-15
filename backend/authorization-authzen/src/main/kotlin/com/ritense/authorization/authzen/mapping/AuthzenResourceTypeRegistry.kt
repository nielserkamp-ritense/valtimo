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

import com.ritense.authorization.authzen.AuthzenProperties

/**
 * Maps Valtimo's fully qualified resource class names to the logical `resource.type` names policies
 * are written against.
 *
 * Valtimo identifies resource types by FQCN, which leaks into request bodies and the frontend. Those
 * names have no business appearing in policy: they would make every class rename a policy migration.
 * The registry keeps the FQCN contract intact on the Valtimo side while policies see stable names
 * like `object` or `zaak`.
 */
class AuthzenResourceTypeRegistry(
    properties: AuthzenProperties,
) {
    private val byClassName: Map<String, String> =
        properties.resourceTypes.mapValues { (_, type) -> type.name }

    /** The logical AuthZEN type name for [resourceType], or null when it is not configured. */
    fun logicalNameOf(resourceType: Class<*>): String? = byClassName[resourceType.name]

    fun isConfigured(resourceType: Class<*>): Boolean = byClassName.containsKey(resourceType.name)

    /** Configured Valtimo class names, for startup validation and diagnostics. */
    fun configuredClassNames(): Set<String> = byClassName.keys
}
