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

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 * Configuration for the AuthZEN Policy Decision Point that answers Valtimo's authorization
 * decisions.
 *
 * ```yaml
 * valtimo:
 *   authorization:
 *     authzen:
 *       enabled: true
 *       url: http://pdp:8443
 *       timeout: 2s
 *       resource-types:
 *         "[com.ritense.objectenapi.security.Object]":
 *           name: object
 * ```
 *
 * Note the **bracket notation** on the resource type key. A key is a fully qualified class name,
 * and Spring's relaxed binding splits an unbracketed key on its dots into nested property names —
 * binding an empty map rather than failing, so the PDP is simply never told about the type and
 * nothing in the logs says why. [AuthzenPropertiesYamlBindingTest] pins both spellings.
 */
@ConfigurationProperties(prefix = "valtimo.authorization.authzen")
data class AuthzenProperties(

    /**
     * Master switch. When false the module contributes no beans at all and Valtimo keeps using its
     * own PBAC implementation. Off by default, in every existing application.
     */
    val enabled: Boolean = false,

    /**
     * Base URL of the PDP. This is **authoritative for scheme, host and port**; only the endpoint
     * *paths* are taken from metadata discovery. See [com.ritense.authorization.authzen.client.AuthzenMetadata].
     */
    val url: String = "http://localhost:8443",

    /** Per-request timeout. A timed-out decision is a denial — there is no PBAC term to fall back to. */
    val timeout: Duration = Duration.ofSeconds(2),

    /**
     * The AuthZEN `subject.type` to send. Cedar policies in `pdp/policies/` are written against
     * `principal is user`, so `user` is also the subject *entity* type — which is why the Valtimo
     * resource type `com.ritense.valtimo.contract.authentication.User` maps to the logical name
     * `managed_user` rather than `user`.
     */
    val subjectType: String = "user",

    /**
     * Largest request body to send in one `/evaluations` call, in bytes. The PDP rejects anything
     * over `PDP_MAX_BODY_SIZE` (`eam/config/server.go:18`), which defaults to 137560. We stay under
     * it and chunk, rather than discovering the limit as a 413 in production.
     */
    val maxBodySize: Int = 120_000,

    /**
     * Valtimo resource type (fully qualified class name) to its AuthZEN mapping. A type absent from
     * this map has no logical name, and requests for it are denied rather than sent to the PDP under
     * a guessed type name.
     */
    val resourceTypes: Map<String, ResourceTypeProperties> = emptyMap(),
) {
    data class ResourceTypeProperties(
        /** The logical `resource.type` sent to the PDP. Never the fully qualified class name. */
        val name: String,
    )
}
