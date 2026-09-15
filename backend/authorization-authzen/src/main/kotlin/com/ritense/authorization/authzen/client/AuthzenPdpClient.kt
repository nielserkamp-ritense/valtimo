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

import com.fasterxml.jackson.databind.ObjectMapper
import com.ritense.authorization.authzen.AuthzenProperties
import com.ritense.authorization.authzen.client.dto.AuthzenActionSearchRequest
import com.ritense.authorization.authzen.client.dto.AuthzenActionSearchResponse
import com.ritense.authorization.authzen.client.dto.AuthzenEntitySearchResponse
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationRequest
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationResponse
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationResponseTyped
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationsRequest
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationsResponse
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationsResponseTyped
import com.ritense.authorization.authzen.client.dto.AuthzenResourceSearchRequest
import com.ritense.authorization.authzen.client.dto.AuthzenSearchRequest
import com.ritense.authorization.authzen.client.dto.AuthzenSearchResponse
import com.ritense.authorization.authzen.client.dto.AuthzenSubjectSearchRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.core.ParameterizedTypeReference
import org.springframework.core.ResolvableType
import org.springframework.web.reactive.function.client.WebClient

/** Raised for any failure to obtain a decision. Always treated as a denial by the caller. */
class AuthzenPdpException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Talks to the AuthZEN PDP's two evaluation endpoints and its three search endpoints.
 *
 * Every failure — transport, timeout, malformed response, cardinality mismatch — raises
 * [AuthzenPdpException]. This client never guesses a decision.
 */
open class AuthzenPdpClient(
    private val webClient: WebClient,
    private val objectMapper: ObjectMapper,
    private val properties: AuthzenProperties,
) {
    private val baseUrl: String = properties.url.trimEnd('/')

    /**
     * Discovered once, on first use. Deliberately not resolved at construction time: a PDP that is
     * still starting up must not prevent the Valtimo context from coming up.
     */
    private val endpoints: AuthzenEndpoints by lazy { discoverEndpoints() }

    open fun evaluate(request: AuthzenEvaluationRequest): Boolean {
        return evaluateWithResponse(request).decision
    }

    open fun evaluateWithResponse(request: AuthzenEvaluationRequest): AuthzenEvaluationResponse {
        val response = post(endpoints.evaluationPath, request, object: ParameterizedTypeReference<AuthzenEvaluationResponse>() {})
        return response
    }

    /**
     * As [evaluateWithResponse], but with the response context bound to [contextType].
     *
     * [contextType] is a real [Class] rather than a type parameter on purpose.
     * `object : ParameterizedTypeReference<AuthzenEvaluationResponseTyped<T>>() {}` compiles, but the
     * anonymous class's generic superclass records `T` as an unbound *type variable* — the method's,
     * erased at runtime. Jackson resolves it to its bound, `Object`, and hands back a `LinkedHashMap`
     * that only fails at the caller's first field access, as a `ClassCastException` nowhere near its
     * cause. A reified type parameter would fix the call site, but `inline`/`reified` cannot be
     * `open`, and this class is open so it can be stubbed.
     */
    open fun <T : Any> evaluateWithResponseType(
        request: AuthzenEvaluationRequest,
        contextType: Class<T>,
    ): AuthzenEvaluationResponseTyped<T> {
        val response = post(
            endpoints.evaluationPath,
            request,
            typeReference<AuthzenEvaluationResponseTyped<T>>(AuthzenEvaluationResponseTyped::class.java, contextType),
        )
        return response
    }

    open fun evaluateAllWithResponse(requests: List<AuthzenEvaluationRequest>): List<AuthzenEvaluationResponse> {
        if (requests.isEmpty()) return emptyList()
        if (requests.size == 1) return listOf(evaluateWithResponse(requests.single()))

        return chunkBySerializedSize(requests).flatMap { chunk ->
            val response = post(
                endpoints.evaluationsPath,
                AuthzenEvaluationsRequest(evaluations = chunk),
                object: ParameterizedTypeReference<AuthzenEvaluationsResponse>() {},
            )
            // A shorter array than requested would silently misalign decisions with the entities
            // they belong to. We always send `execute_all` precisely so this cannot happen, so a
            // mismatch means the PDP did something we do not understand — fail, do not guess.
            if (response.evaluations.size != chunk.size) {
                throw AuthzenPdpException(
                    "AuthZEN PDP returned ${response.evaluations.size} decisions for ${chunk.size} " +
                        "evaluations. Refusing to align them by position."
                )
            }
            response.evaluations
        }
    }

    /** As [evaluateAllWithResponse], but with each response context bound to [contextType]. */
    open fun <T : Any> evaluateAllWithResponseType(
        requests: List<AuthzenEvaluationRequest>,
        contextType: Class<T>,
    ): List<AuthzenEvaluationResponseTyped<T>> {
        if (requests.isEmpty()) return emptyList()
        if (requests.size == 1) return listOf(evaluateWithResponseType(requests.single(), contextType))

        return chunkBySerializedSize(requests).flatMap { chunk ->
            val response = post(
                endpoints.evaluationsPath,
                AuthzenEvaluationsRequest(evaluations = chunk),
                typeReference<AuthzenEvaluationsResponseTyped<T>>(AuthzenEvaluationsResponseTyped::class.java, contextType),
            )
            // A shorter array than requested would silently misalign decisions with the entities
            // they belong to. We always send `execute_all` precisely so this cannot happen, so a
            // mismatch means the PDP did something we do not understand — fail, do not guess.
            if (response.evaluations.size != chunk.size) {
                throw AuthzenPdpException(
                    "AuthZEN PDP returned ${response.evaluations.size} decisions for ${chunk.size} " +
                        "evaluations. Refusing to align them by position."
                )
            }
            response.evaluations
        }
    }

    open fun evaluateAll(requests: List<AuthzenEvaluationRequest>): List<Boolean> {
        return evaluateAllWithResponse(requests).map { it.decision }
    }

    /**
     * Ids of the subjects of `subject.type` that may perform the request's action on its resource.
     *
     * The subject carries no id — that is what is being searched for.
     */
    open fun searchSubjects(request: AuthzenSubjectSearchRequest): List<String> =
        search(endpoints.searchSubjectPath, SUBJECT, request, object: ParameterizedTypeReference<AuthzenActionSearchResponse>() {})

    /**
     * Ids of the resources of `resource.type` the request's subject may perform its action on.
     *
     * **This is not policy enumeration.** The PDP reads one PIP attribute named
     * `resources.<type>` — a comma-separated string of candidate ids — and evaluates every candidate
     * in it (`eam/pdp/controller/search.go:49-58`). The caller cannot supply candidates, the answer
     * is bounded by whatever that attribute holds, and a type with no such attribute is a *failure*,
     * not an empty answer. See the module README before building query filtering on this.
     */
    open fun searchResources(request: AuthzenResourceSearchRequest): List<String> =
        search(endpoints.searchResourcePath, RESOURCE, request, object: ParameterizedTypeReference<AuthzenEntitySearchResponse>() {})

    /** Names of the actions the request's subject may perform on its resource. */
    open fun searchActions(request: AuthzenActionSearchRequest): List<String> =
        search(endpoints.searchActionPath, ACTION, request, object: ParameterizedTypeReference<AuthzenActionSearchResponse>() {})

    /**
     * Runs one search to exhaustion, following `next_token` until the PDP stops handing one out.
     *
     * Paging is invisible to the caller, as chunking is in [evaluateAll]. It is not free: the PDP
     * scans and evaluates the *whole* candidate list on every page and slices afterwards
     * (`authzen_search.go:197-217`), so page N costs the same as page 1. A request's `page.limit`
     * therefore only trades body size against the number of full scans.
     */
    private fun <T : AuthzenSearchResponse> search(
        path: String?,
        dimension: String,
        request: AuthzenSearchRequest,
        responseType: ParameterizedTypeReference<T>,
    ): List<String> {
        if (path == null) {
            throw AuthzenPdpException(
                "The AuthZEN PDP at $baseUrl does not advertise a $dimension search endpoint, so it " +
                    "cannot answer one. Its metadata lists only what it has switched on."
            )
        }

        val found = mutableListOf<String>()
        var body = request
        var token: String? = null
        var pages = 0

        while (true) {
            val response = post(path, body, responseType)

            // No `results` array at all is how a *failed* search arrives: the PDP reports search
            // failures with HTTP 200 and an error body (`authzen_search.go:186-189`). Reading that as
            // an empty list would report "nothing is allowed" for a search that never ran.
            val values = response.values ?: throw AuthzenPdpException(
                "AuthZEN PDP $dimension search at $baseUrl$path answered without a 'results' array" +
                    response.detail?.let { ": '$it'" }.orEmpty() + ". The PDP reports a failed search " +
                    "as HTTP 200 with an error body, so this is a failure, not an empty result set. " +
                    "Its own log carries the cause — most often the candidate list is missing, as " +
                    "'attribute [${dimension}s.<type>] not found'."
            )
            if (values.any { it.isBlank() }) {
                throw AuthzenPdpException(
                    "AuthZEN PDP $dimension search at $baseUrl$path returned a result with no " +
                        "identifier. Refusing to treat it as a match."
                )
            }
            found += values
            pages++

            val next = response.page?.nextToken?.takeIf { it.isNotBlank() }
            if (next == null) {
                if (pages > 1) {
                    logger.debug { "Read the $dimension search across $pages pages, ${found.size} results." }
                }
                return found
            }
            // Both guards are about a PDP that never finishes paging. The token encodes an offset
            // (`authzen_search.go:265-268`), so an unchanged one means the last page made no progress.
            if (next == token) {
                throw AuthzenPdpException(
                    "AuthZEN PDP $dimension search at $baseUrl$path repeated page token '$next'. " +
                        "Refusing to page forever."
                )
            }
            if (pages >= MAX_SEARCH_PAGES) {
                throw AuthzenPdpException(
                    "AuthZEN PDP $dimension search at $baseUrl$path is still paging after " +
                        "$MAX_SEARCH_PAGES pages (${found.size} results). Refusing to continue."
                )
            }
            token = next
            body = request.withPageToken(next)
        }
    }

    /**
     * Splits [requests] so each chunk's serialized body stays under [AuthzenProperties.maxBodySize].
     *
     * A single entry larger than the limit still gets its own chunk — it will fail at the PDP, and
     * that failure is more useful than a silently dropped evaluation.
     */
    private fun chunkBySerializedSize(requests: List<AuthzenEvaluationRequest>): List<List<AuthzenEvaluationRequest>> {
        val chunks = mutableListOf<List<AuthzenEvaluationRequest>>()
        var current = mutableListOf<AuthzenEvaluationRequest>()
        var currentSize = ENVELOPE_OVERHEAD_BYTES

        requests.forEach { request ->
            val size = objectMapper.writeValueAsBytes(request).size + 1 // + comma
            if (current.isNotEmpty() && currentSize + size > properties.maxBodySize) {
                chunks.add(current)
                current = mutableListOf()
                currentSize = ENVELOPE_OVERHEAD_BYTES
            }
            current.add(request)
            currentSize += size
        }
        if (current.isNotEmpty()) chunks.add(current)

        if (chunks.size > 1) {
            logger.debug { "Split ${requests.size} AuthZEN evaluations across ${chunks.size} requests." }
        }
        return chunks
    }

    private fun discoverEndpoints(): AuthzenEndpoints {
        return try {
            val document = webClient.get()
                .uri("$baseUrl${AuthzenMetadataReader.WELL_KNOWN_PATH}")
                .retrieve()
                .bodyToMono(AuthzenConfigurationDocument::class.java)
                .block(properties.timeout)
            AuthzenMetadataReader.read(document).also {
                logger.info { "Discovered AuthZEN endpoints at $baseUrl: $it" }
            }
        } catch (e: Exception) {
            logger.warn(e) {
                "Could not read $baseUrl${AuthzenMetadataReader.WELL_KNOWN_PATH}. Falling back to the " +
                    "paths OpenFTV serves today: ${AuthzenEndpoints.OPEN_FTV_DEFAULT}"
            }
            AuthzenEndpoints.OPEN_FTV_DEFAULT
        }
    }

    /**
     * A [ParameterizedTypeReference] for `raw<arguments…>` built from runtime classes.
     *
     * The reference carries a [ResolvableType]-synthesised `ParameterizedType` whose arguments are
     * `Class` objects, so nothing about it is erased and Jackson binds the context to the type asked
     * for. `R` is unchecked — it is the caller's assertion that it spelled `raw<arguments…>`
     * correctly, which the two call sites above do one line apart from their `R`.
     */
    private fun <R : Any> typeReference(raw: Class<*>, vararg arguments: Class<*>): ParameterizedTypeReference<R> =
        ParameterizedTypeReference.forType(ResolvableType.forClassWithGenerics(raw, *arguments).type)

    private fun <T : Any> post(path: String, body: Any, responseType: ParameterizedTypeReference<T>): T {
        try {
            return webClient.post()
                .uri("$baseUrl$path")
                .bodyValue(body)
                .also {
                    logger.debug { "Posted $path to $responseType with body \n\n $body \n\n" }
                }
                .retrieve()
                .bodyToMono(responseType)
                .block(properties.timeout)
                .also {
                    logger.debug { "Posted $path to $responseType with results $it" }
                }
                ?: throw AuthzenPdpException("AuthZEN PDP returned an empty body from $path")
        } catch (e: AuthzenPdpException) {
            throw e
        } catch (e: Exception) {
            throw AuthzenPdpException("AuthZEN PDP call to $baseUrl$path failed: ${e.message}", e)
        }
    }

    companion object {
        private val logger = KotlinLogging.logger {}

        /** `{"evaluations":[],"options":{"evaluation_semantics":"execute_all"}}` and slack. */
        private const val ENVELOPE_OVERHEAD_BYTES = 128

        /**
         * Ceiling on pages followed for one search. At the PDP's default page size of 10000 this is
         * a million results — far past anything a policy question should return, and reached only by
         * a PDP that is paging without progressing.
         */
        private const val MAX_SEARCH_PAGES = 100

        private const val SUBJECT = "subject"
        private const val ACTION = "action"
        private const val RESOURCE = "resource"
    }
}
