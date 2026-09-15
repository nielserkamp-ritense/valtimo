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

package com.ritense.authorization.authzen.client

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import io.github.oshai.kotlinlogging.KotlinLogging
import java.net.URI

/**
 * The endpoint paths this client will POST to.
 *
 * These are discovered rather than hardcoded because OpenFTV serves the AuthZEN API under
 * `/authzen/v1`, not the specification's `/access/v1`.
 */
data class AuthzenEndpoints(
    val evaluationPath: String,
    val evaluationsPath: String,
    /**
     * Null when a metadata document was read and did not advertise the endpoint.
     *
     * Unlike the evaluation paths these are **not** defaulted on absence: OpenFTV leaves a search
     * endpoint out of its metadata exactly when that API is switched off
     * (`eam/handlers/fiber/authzen.go:83-91`) and answers a call to the path with `501`. Keeping the
     * absence lets the client say "this PDP does not do subject search" instead of relaying a bare
     * 501 from a path it should not have called.
     */
    val searchSubjectPath: String? = null,
    val searchActionPath: String? = null,
    val searchResourcePath: String? = null,
) {
    companion object {
        /**
         * What OpenFTV serves today (`eam/handlers/fiber/consts.go:28,29,47-49`). Used when
         * discovery fails, so a PDP that cannot serve its own metadata document still gets talked to
         * correctly. The search paths are included: with no document to read there is nothing that
         * says the APIs are off, and a switched-off one then surfaces as the PDP's own 501.
         */
        val OPEN_FTV_DEFAULT = AuthzenEndpoints(
            evaluationPath = "/authzen/v1/evaluation",
            evaluationsPath = "/authzen/v1/evaluations",
            searchSubjectPath = "/authzen/v1/search/subject",
            searchActionPath = "/authzen/v1/search/action",
            searchResourcePath = "/authzen/v1/search/resource",
        )
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenConfigurationDocument(
    @param:JsonProperty("access_evaluation_endpoint")
    val accessEvaluationEndpoint: String? = null,
    @param:JsonProperty("access_evaluations_endpoint")
    val accessEvaluationsEndpoint: String? = null,
    @param:JsonProperty("search_subject_endpoint")
    val searchSubjectEndpoint: String? = null,
    @param:JsonProperty("search_action_endpoint")
    val searchActionEndpoint: String? = null,
    @param:JsonProperty("search_resource_endpoint")
    val searchResourceEndpoint: String? = null,
)

/**
 * Turns a `/.well-known/authzen-configuration` document into [AuthzenEndpoints].
 *
 * **Only the path is taken from the document.** The PDP advertises *absolute* URLs built from its
 * own view of its base address — asked over `localhost` it answers `http://localhost:8443`, which
 * from inside a container or behind a gateway points somewhere else entirely. Honouring the
 * advertised host would send authorization decisions to an unintended destination, so the
 * configured [AuthzenProperties.url] stays authoritative for scheme, host and port and we keep
 * only the path component.
 */
object AuthzenMetadataReader {

    private val logger = KotlinLogging.logger {}

    const val WELL_KNOWN_PATH = "/.well-known/authzen-configuration"

    fun read(document: AuthzenConfigurationDocument?): AuthzenEndpoints {
        if (document == null) return AuthzenEndpoints.OPEN_FTV_DEFAULT
        return AuthzenEndpoints(
            evaluationPath = pathOf(document.accessEvaluationEndpoint)
                ?: AuthzenEndpoints.OPEN_FTV_DEFAULT.evaluationPath,
            evaluationsPath = pathOf(document.accessEvaluationsEndpoint)
                ?: AuthzenEndpoints.OPEN_FTV_DEFAULT.evaluationsPath,
            searchSubjectPath = pathOf(document.searchSubjectEndpoint),
            searchActionPath = pathOf(document.searchActionEndpoint),
            searchResourcePath = pathOf(document.searchResourceEndpoint),
        )
    }

    /** Extracts the path from an advertised endpoint, discarding any scheme/host/port. */
    private fun pathOf(endpoint: String?): String? {
        if (endpoint.isNullOrBlank()) return null
        val path = try {
            URI(endpoint).path
        } catch (e: IllegalArgumentException) {
            logger.warn { "AuthZEN metadata advertised an unparseable endpoint '$endpoint'; ignoring it. ${e.message}" }
            return null
        }
        if (path.isNullOrBlank()) return null

        val advertisedHost = runCatching { URI(endpoint).host }.getOrNull()
        if (advertisedHost != null) {
            logger.debug {
                "AuthZEN metadata advertised host '$advertisedHost' for '$path'. Using the configured " +
                    "PDP URL instead — the PDP reports its own view of its address, which is not " +
                    "necessarily reachable from here."
            }
        }
        return path
    }
}
