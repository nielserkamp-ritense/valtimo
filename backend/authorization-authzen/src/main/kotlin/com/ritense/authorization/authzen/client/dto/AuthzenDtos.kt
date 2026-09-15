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

package com.ritense.authorization.authzen.client.dto

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

/**
 * AuthZEN 1.4 wire types, matching `open-ftv/oas/authzen/authzen.go`.
 *
 * Covers the two evaluation endpoints and the three search endpoints (`search/subject`,
 * `search/action`, `search/resource`). Search is *callable*, which is not the same as being able to
 * answer Valtimo's query filtering — see the module README for what the PDP's search actually does.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenSubject(
    val type: String,
    val id: String,
    val properties: Map<String, Any?>? = null,
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenResource(
    val type: String,
    /**
     * Never null. The PDP rejects an evaluation whose resource has no id with `400 invalid
     * resource`, so a request that is not about one specific instance sends
     * [com.ritense.authorization.authzen.mapping.AuthzenRequestMapper.ANY_RESOURCE_ID].
     */
    val id: String,
    val properties: Map<String, Any?>? = null,
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenAction(
    val name: String,
    val properties: Map<String, Any?>? = null,
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenEvaluationRequest(
    val subject: AuthzenSubject,
    val resource: AuthzenResource,
    val action: AuthzenAction,
    val context: Map<String, Any?>? = null,
)

/**
 * A decision, and the response context beside it.
 *
 * [context] is deliberately an untyped map, with no accessor per property: besides `id` and
 * `reason_user`, the PDP publishes **every property the matched policy defines** as a property of
 * this object, under the name the policy chose. Which properties exist is the policy author's
 * business, not this client's — a caller that expects one reads `context["<name>"]` and copes with
 * its absence.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenEvaluationResponse(
    val decision: Boolean = false,
    val context: Map<String, Any?>? = null,
)

/**
 * [AuthzenEvaluationResponse] with the response context bound to a type of the caller's choosing.
 *
 * Obtainable only from `AuthzenPdpClient.evaluateWithResponseType`, which takes the context type as a
 * `Class`: a `T` supplied as a type argument alone is erased before Jackson ever sees it.
 *
 * [context] is nullable and defaults to null because a decision may well arrive without one — a
 * policy publishes context only if it has something to say.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenEvaluationResponseTyped<T>(
    val decision: Boolean = false,
    val context: T? = null,
)

/**
 * Batch request. Top-level subject/resource/action act as defaults for entries that omit them.
 *
 * Two traps in the PDP's default handling, both in `eam/handlers/fiber/authzen_evaluations.go`:
 * defaults are applied **per field and all-or-nothing** — supplying any entry-level `properties`
 * replaces the whole default map rather than merging it (`:82,92`) — and the top-level [context] is
 * **not** inherited by entries (`:119`). We therefore send every entry fully populated and use the
 * defaults for nothing, which costs a few bytes and removes the whole class of bug.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenEvaluationsRequest(
    val evaluations: List<AuthzenEvaluationRequest>,
    val options: AuthzenEvaluationsOptions = AuthzenEvaluationsOptions(),
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenEvaluationsOptions(
    /**
     * Always `execute_all`. The short-circuiting modes (`deny_on_first_deny`,
     * `permit_on_first_permit`) return a *shorter* array than requested, which would silently
     * misalign decisions with the entities they belong to.
     */
    @get:JsonProperty("evaluation_semantics")
    val evaluationSemantics: String = "execute_all",
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenEvaluationsResponse(
    val evaluations: List<AuthzenEvaluationResponse> = emptyList(),
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenEvaluationsResponseTyped<T>(
    val evaluations: List<AuthzenEvaluationResponseTyped<T>> = emptyList(),
)

// ---- search --------------------------------------------------------------------------------------

/**
 * The subject of a subject search: a type, and optionally properties, but **no id** — the ids are
 * what the search returns.
 *
 * The id is absent from the type rather than nullable on [AuthzenSubject] because the PDP dispatches
 * a search on *which* id is empty (`eam/pdp/controller/search.go:14-21`). A subject id smuggled into
 * a subject search does not fail: it silently turns the call into an action or resource search.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenSearchSubject(
    val type: String,
    val properties: Map<String, Any?>? = null,
)

/** The resource of a resource search. Carries no id, for the same reason as [AuthzenSearchSubject]. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenSearchResource(
    val type: String,
    val properties: Map<String, Any?>? = null,
)

/**
 * Pagination on the way in.
 *
 * [limit] is the *page* size, not a cap on the answer: the client follows `next_token` to the end.
 * Leaving it null takes the PDP's own default of 10000 (`authzen_search.go:200`).
 *
 * [token] is filled in by [com.ritense.authorization.authzen.client.AuthzenPdpClient] while it
 * follows the pages. Callers leave it null — a token is an opaque offset into a result set, and one
 * supplied from outside starts reading in the middle of a list whose beginning nobody saw.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenPageRequest(
    val limit: Int? = null,
    val token: String? = null,
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenPageResponse(
    val count: Int? = null,
    val total: Int? = null,
    @param:JsonProperty("next_token")
    val nextToken: String? = null,
)

/** Lets the client re-send any of the three search requests with the next page's token. */
sealed interface AuthzenSearchRequest {
    val page: AuthzenPageRequest?
    fun withPageToken(token: String): AuthzenSearchRequest
}

/** "Which subjects of this type may perform [action] on [resource]?" */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenSubjectSearchRequest(
    val subject: AuthzenSearchSubject,
    val resource: AuthzenResource,
    val action: AuthzenAction,
    val context: Map<String, Any?>? = null,
    override val page: AuthzenPageRequest? = null,
) : AuthzenSearchRequest {
    override fun withPageToken(token: String) = copy(page = (page ?: AuthzenPageRequest()).copy(token = token))
}

/** "Which resources of this type may [subject] perform [action] on?" */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenResourceSearchRequest(
    val subject: AuthzenSubject,
    val resource: AuthzenSearchResource,
    val action: AuthzenAction,
    val context: Map<String, Any?>? = null,
    override val page: AuthzenPageRequest? = null,
) : AuthzenSearchRequest {
    override fun withPageToken(token: String) = copy(page = (page ?: AuthzenPageRequest()).copy(token = token))
}

/**
 * "Which actions may [subject] perform on [resource]?"
 *
 * Carries no action at all: the PDP fills in an empty one itself
 * (`eam/handlers/fiber/authzen_search.go:63`), and that emptiness is what selects an action search.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthzenActionSearchRequest(
    val subject: AuthzenSubject,
    val resource: AuthzenResource,
    val context: Map<String, Any?>? = null,
    override val page: AuthzenPageRequest? = null,
) : AuthzenSearchRequest {
    override fun withPageToken(token: String) = copy(page = (page ?: AuthzenPageRequest()).copy(token = token))
}

/**
 * The two search response shapes, reduced to the one thing a caller wants: the values found.
 *
 * [values] is **null when the body carried no `results` array**, which is how a failure arrives: the
 * PDP answers a failed search with HTTP 200 and an error body (`authzen_search.go:186-189`). A
 * client that read a missing array as an empty list would report "nothing allowed" for a search that
 * never ran.
 */
sealed interface AuthzenSearchResponse {
    @get:JsonIgnore
    val values: List<String>?
    val page: AuthzenPageResponse?

    /**
     * The `detail` of the error body that arrives in place of results — "AuthZEN subject search
     * failed". Generic by design: the PDP keeps the cause (`attribute [subjects.user] not found`)
     * in its own log. Worth quoting anyway, since it separates "the PDP failed the search" from
     * "the PDP sent something this client could not read".
     */
    val detail: String?
}

/** Response of both `search/subject` and `search/resource`; their result shape is identical. */
@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenEntitySearchResponse(
    val results: List<AuthzenSearchResult>? = null,
    override val page: AuthzenPageResponse? = null,
    override val detail: String? = null,
) : AuthzenSearchResponse {
    @get:JsonIgnore
    override val values: List<String>? get() = results?.map { it.id }
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenActionSearchResponse(
    val results: List<AuthzenActionSearchResult>? = null,
    override val page: AuthzenPageResponse? = null,
    override val detail: String? = null,
) : AuthzenSearchResponse {
    @get:JsonIgnore
    override val values: List<String>? get() = results?.map { it.name }
}

/** Blank [id] means the PDP omitted it; the client raises rather than returning it as a match. */
@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenSearchResult(
    val type: String? = null,
    val id: String = "",
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthzenActionSearchResult(
    val name: String = "",
)
