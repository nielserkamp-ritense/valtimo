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
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.ritense.authorization.authzen.AuthzenProperties
import com.ritense.authorization.authzen.client.dto.AuthzenAction
import com.ritense.authorization.authzen.client.dto.AuthzenActionSearchRequest
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationRequest
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationResponse
import com.ritense.authorization.authzen.client.dto.AuthzenPageRequest
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenResourceSearchRequest
import com.ritense.authorization.authzen.client.dto.AuthzenSearchResource
import com.ritense.authorization.authzen.client.dto.AuthzenSearchSubject
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.authzen.client.dto.AuthzenSubjectSearchRequest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.web.reactive.function.client.WebClient

class AuthzenPdpClientTest {

    private lateinit var server: MockWebServer
    private val objectMapper = ObjectMapper().registerKotlinModule()

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun client(properties: AuthzenProperties.() -> AuthzenProperties = { this }) = AuthzenPdpClient(
        WebClient.builder().build(),
        objectMapper,
        AuthzenProperties(enabled = true, url = server.url("/").toString().trimEnd('/')).properties(),
    )

    private fun evaluation(id: String = "1") = AuthzenEvaluationRequest(
        subject = AuthzenSubject(type = "user", id = "alice"),
        resource = AuthzenResource(type = "zaak", id = id),
        action = AuthzenAction(name = "view"),
    )

    private fun json(body: String) = MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody(body)

    private fun metadata() = json(
        """{"access_evaluation_endpoint":"http://localhost:8443/authzen/v1/evaluation",
            "access_evaluations_endpoint":"http://localhost:8443/authzen/v1/evaluations",
            "search_subject_endpoint":"http://localhost:8443/authzen/v1/search/subject",
            "search_action_endpoint":"http://localhost:8443/authzen/v1/search/action",
            "search_resource_endpoint":"http://localhost:8443/authzen/v1/search/resource"}"""
    )

    /** Drains the discovery call so assertions can look at the request that followed it. */
    private fun takeRequestAfterDiscovery(): RecordedRequest {
        server.takeRequest() // /.well-known/authzen-configuration
        return server.takeRequest()
    }

    // ---- single evaluation ---------------------------------------------------------------------

    @Test
    fun `should return the decision from a single evaluation`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"decision":true}"""))

        assertTrue(client().evaluate(evaluation()))
    }

    @Test
    fun `should treat a missing decision field as a denial`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"context":{"id":"not-authorized"}}"""))

        assertEquals(false, client().evaluate(evaluation()))
    }

    // ---- response context -----------------------------------------------------------------------

    /**
     * The PDP publishes every property the matched policy defines as a property of the response
     * context, under the policy's own names — `filterOn` here is one of them, not a field this
     * client knows. The body is one the PDP actually returned for a ROLE_ADMIN zaak view.
     *
     * Asserted on the DTO rather than through [AuthzenPdpClient.evaluate], which answers a bare
     * `Boolean` and drops the context — the day something filters a query, it reads this.
     */
    @Test
    fun `should capture whatever properties the policy published`() {
        val body = """
            {"context":{"codes":["ZAAK_VIEW_ROLE_ADMIN"],
                        "filterOn":{"zaaktype":["$PERMITTED_ZAAKTYPE"]},
                        "id":"ok",
                        "policies":["zaak-role-admin-view"],
                        "reason_user":{"en":"ROLE_ADMIN may view a zaak of the permitted zaaktype"}},
             "decision":true}
        """.trimIndent()

        val response = objectMapper.readValue(body, AuthzenEvaluationResponse::class.java)

        assertTrue(response.decision)
        assertEquals(mapOf("zaaktype" to listOf(PERMITTED_ZAAKTYPE)), response.context?.get("filterOn"))
        assertEquals(listOf("zaak-role-admin-view"), response.context?.get("policies"))
    }

    /** A policy that published nothing leaves a context with only the PDP's own properties. */
    @Test
    fun `should leave the context bare when the policy published nothing`() {
        val body = """{"context":{"id":"ok","reason_user":{"en":"ok"}},"decision":true}"""

        val context = objectMapper.readValue(body, AuthzenEvaluationResponse::class.java).context

        assertEquals(setOf("id", "reason_user"), context?.keys)
    }

    // ---- typed response context -----------------------------------------------------------------

    /** A caller's own reading of the context, shaped like the `filter` the rego policies publish. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    data class FilterContext(val filter: List<Constraint> = emptyList()) {
        data class Constraint(val field: String, val op: String, val value: String)
    }

    /**
     * The reason `evaluateWithResponseType` takes a `Class` and not just a type argument.
     *
     * Bound through a type argument alone, the context arrives as a `LinkedHashMap` — the failure
     * lands on the *caller's* first field access as a `ClassCastException`, so this test passing is
     * the only place the binding is checked.
     */
    @Test
    fun `should bind a single evaluation's context to the requested type`() {
        server.enqueue(metadata())
        server.enqueue(
            json(
                """{"decision":true,
                    "context":{"id":"ok",
                               "filter":[{"field":"zaaktype","op":"==","value":"$PERMITTED_ZAAKTYPE"}]}}"""
            )
        )

        val response = client().evaluateWithResponseType(evaluation(), FilterContext::class.java)

        assertTrue(response.decision)
        assertEquals(
            listOf(FilterContext.Constraint("zaaktype", "==", PERMITTED_ZAAKTYPE)),
            response.context?.filter,
        )
    }

    /** The same binding through the batch endpoint, whose response nests the context one deeper. */
    @Test
    fun `should bind every context in a batch to the requested type`() {
        server.enqueue(metadata())
        server.enqueue(
            json(
                """{"evaluations":[
                     {"decision":true,"context":{"filter":[{"field":"zaaktype","op":"==","value":"a"}]}},
                     {"decision":true,"context":{"filter":[{"field":"zaaktype","op":"==","value":"b"}]}}]}"""
            )
        )

        val responses = client().evaluateAllWithResponseType(
            listOf(evaluation("1"), evaluation("2")),
            FilterContext::class.java,
        )

        assertEquals(
            listOf("a", "b"),
            responses.flatMap { it.context?.filter.orEmpty() }.map { it.value },
        )
    }

    /** A decision with nothing to say publishes no context at all, which is not a failure. */
    @Test
    fun `should accept a typed decision that carries no context`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"decision":false}"""))

        val response = client().evaluateWithResponseType(evaluation(), FilterContext::class.java)

        assertFalse(response.decision)
        assertNull(response.context)
    }

    // ---- metadata discovery --------------------------------------------------------------------

    /**
     * The PDP advertises absolute URLs built from its own view of its address — `localhost:8443`
     * even when reached over a container network. Honouring the advertised host would send
     * authorization decisions somewhere unintended, so only the *path* is taken from metadata.
     */
    @Test
    fun `should keep the configured host and take only the path from metadata`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"decision":true}"""))

        client().evaluate(evaluation())

        val request = takeRequestAfterDiscovery()
        assertEquals("/authzen/v1/evaluation", request.path)
        assertEquals(server.hostName, request.requestUrl!!.host)
        assertEquals(server.port, request.requestUrl!!.port)
    }

    /** A PDP that cannot serve its own metadata still gets talked to on the paths OpenFTV serves. */
    @Test
    fun `should fall back to the OpenFTV default paths when discovery fails`() {
        server.enqueue(MockResponse().setResponseCode(404))
        server.enqueue(json("""{"decision":true}"""))

        client().evaluate(evaluation())

        assertEquals(AuthzenEndpoints.OPEN_FTV_DEFAULT.evaluationPath, takeRequestAfterDiscovery().path)
    }

    // ---- batch -----------------------------------------------------------------------------------

    @Test
    fun `should return decisions in request order`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"evaluations":[{"decision":true},{"decision":false},{"decision":true}]}"""))

        val decisions = client().evaluateAll(listOf(evaluation("1"), evaluation("2"), evaluation("3")))

        assertEquals(listOf(true, false, true), decisions)
    }

    @Test
    fun `should always request execute_all semantics`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"evaluations":[{"decision":true},{"decision":true}]}"""))

        client().evaluateAll(listOf(evaluation("1"), evaluation("2")))

        val body = takeRequestAfterDiscovery().body.readUtf8()
        assertTrue(body.contains("\"evaluation_semantics\":\"execute_all\""), body)
    }

    /**
     * The short-circuiting semantics return a shorter array than requested. We never ask for them,
     * so a mismatch means the PDP did something we do not understand — aligning decisions with
     * entities by position anyway would silently authorize the wrong thing.
     */
    @Test
    fun `should refuse to align a short response with the request`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"evaluations":[{"decision":true}]}"""))

        val exception = assertThrows<AuthzenPdpException> {
            client().evaluateAll(listOf(evaluation("1"), evaluation("2"), evaluation("3")))
        }
        assertTrue(exception.message!!.contains("Refusing to align"))
    }

    @Test
    fun `should send a single evaluation rather than a batch of one`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"decision":true}"""))

        client().evaluateAll(listOf(evaluation()))

        assertEquals("/authzen/v1/evaluation", takeRequestAfterDiscovery().path)
    }

    @Test
    fun `should not call the PDP for an empty batch`() {
        assertEquals(emptyList<Boolean>(), client().evaluateAll(emptyList()))
        assertEquals(0, server.requestCount)
    }

    // ---- chunking --------------------------------------------------------------------------------

    /**
     * The PDP rejects a body over `PDP_MAX_BODY_SIZE` (137560 bytes by default). Chunking keeps that
     * from surfacing as a 413 in production, and must stay invisible to the caller.
     */
    @Test
    fun `should split an oversized batch across requests and preserve order`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"evaluations":[{"decision":true},{"decision":false}]}"""))
        server.enqueue(json("""{"evaluations":[{"decision":true},{"decision":true}]}"""))

        // A tiny limit forces two entries per chunk without building a huge fixture.
        val small = client { copy(maxBodySize = 128 + 2 * approximateEntrySize()) }
        val decisions = small.evaluateAll(List(4) { evaluation(it.toString()) })

        assertEquals(listOf(true, false, true, true), decisions)
        assertEquals(3, server.requestCount) // discovery + two batches
    }

    private fun approximateEntrySize() = objectMapper.writeValueAsBytes(evaluation("0")).size + 1

    // ---- failure posture -------------------------------------------------------------------------

    @Test
    fun `should raise rather than guess when the PDP returns an error status`() {
        server.enqueue(metadata())
        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":"invalid resource"}"""))

        assertThrows<AuthzenPdpException> { client().evaluate(evaluation()) }
    }

    @Test
    fun `should raise rather than guess when the PDP returns nothing`() {
        server.enqueue(metadata())
        server.enqueue(MockResponse().setResponseCode(500))

        assertThrows<AuthzenPdpException> { client().evaluate(evaluation()) }
    }

    // ---- search ----------------------------------------------------------------------------------

    private fun subjectSearch() = AuthzenSubjectSearchRequest(
        subject = AuthzenSearchSubject(type = "user"),
        resource = AuthzenResource(type = "zaak", id = "1"),
        action = AuthzenAction(name = "view"),
    )

    private fun resourceSearch(page: AuthzenPageRequest? = null) = AuthzenResourceSearchRequest(
        subject = AuthzenSubject(type = "user", id = "alice"),
        resource = AuthzenSearchResource(type = "zaak"),
        action = AuthzenAction(name = "view"),
        page = page,
    )

    private fun actionSearch() = AuthzenActionSearchRequest(
        subject = AuthzenSubject(type = "user", id = "alice"),
        resource = AuthzenResource(type = "zaak", id = "1"),
    )

    @Test
    fun `should return the ids a resource search found`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[{"type":"zaak","id":"1"},{"type":"zaak","id":"2"}],"page":{"count":2}}"""))

        assertEquals(listOf("1", "2"), client().searchResources(resourceSearch()))
        assertEquals("/authzen/v1/search/resource", takeRequestAfterDiscovery().path)
    }

    @Test
    fun `should return the ids a subject search found`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[{"type":"user","id":"alice"},{"type":"user","id":"bob"}]}"""))

        assertEquals(listOf("alice", "bob"), client().searchSubjects(subjectSearch()))
        assertEquals("/authzen/v1/search/subject", takeRequestAfterDiscovery().path)
    }

    @Test
    fun `should return the names an action search found`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[{"name":"view"},{"name":"modify"}]}"""))

        assertEquals(listOf("view", "modify"), client().searchActions(actionSearch()))
        assertEquals("/authzen/v1/search/action", takeRequestAfterDiscovery().path)
    }

    @Test
    fun `should return an empty list for a search that found nothing`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[],"page":{"count":0,"total":0}}"""))

        assertEquals(emptyList<String>(), client().searchResources(resourceSearch()))
    }

    /**
     * The PDP dispatches on *which* id is empty (`eam/pdp/controller/search.go:14-21`), so a subject
     * id in a subject search does not fail — it silently becomes a different search. The request
     * types have no id field for the dimension being searched; this pins that it stays off the wire.
     */
    @Test
    fun `should not send an id for the dimension being searched`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[]}"""))

        client().searchResources(resourceSearch())

        val body = objectMapper.readTree(takeRequestAfterDiscovery().body.readUtf8())
        assertFalse(body.path("resource").has("id"), body.toString())
        assertEquals("alice", body.path("subject").path("id").asText())
    }

    /** An action search carries no action at all — the PDP supplies an empty one, and that empty
     * action is what selects an action search. */
    @Test
    fun `should not send an action for an action search`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[]}"""))

        client().searchActions(actionSearch())

        val body = objectMapper.readTree(takeRequestAfterDiscovery().body.readUtf8())
        assertFalse(body.has("action"), body.toString())
    }

    // ---- search pagination -----------------------------------------------------------------------

    @Test
    fun `should follow next_token until the PDP stops paging`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[{"id":"1"},{"id":"2"}],"page":{"count":2,"next_token":"b2Zmc2V0OjI="}}"""))
        server.enqueue(json("""{"results":[{"id":"3"}],"page":{"count":1}}"""))

        val found = client().searchResources(resourceSearch(AuthzenPageRequest(limit = 2)))

        assertEquals(listOf("1", "2", "3"), found)
        assertEquals(3, server.requestCount) // discovery + two pages

        server.takeRequest() // discovery
        val first = objectMapper.readTree(server.takeRequest().body.readUtf8())
        val second = objectMapper.readTree(server.takeRequest().body.readUtf8())
        assertFalse(first.path("page").has("token"))
        assertEquals("b2Zmc2V0OjI=", second.path("page").path("token").asText())
        assertEquals(2, second.path("page").path("limit").asInt()) // the caller's page size survives
    }

    /** The token encodes an offset, so an unchanged one means the last page made no progress. */
    @Test
    fun `should refuse to page forever on a repeated token`() {
        server.enqueue(metadata())
        repeat(2) {
            server.enqueue(json("""{"results":[{"id":"1"}],"page":{"next_token":"stuck"}}"""))
        }

        val exception = assertThrows<AuthzenPdpException> { client().searchResources(resourceSearch()) }

        assertTrue(exception.message!!.contains("repeated page token"), exception.message)
    }

    // ---- search failure posture ------------------------------------------------------------------

    /**
     * The trap this client exists to absorb: the PDP answers a *failed* search with HTTP 200 and an
     * error body (`authzen_search.go:186-189`). A client checking only the status code reads that as
     * "zero results allowed" — the missing `results` array is the only signal that the search never
     * ran.
     */
    @Test
    fun `should raise when a 200 response carries no results array`() {
        server.enqueue(metadata())
        server.enqueue(
            json("""{"status":200,"title":"OK","detail":"AuthZEN resource search failed"}""")
        )

        val exception = assertThrows<AuthzenPdpException> { client().searchResources(resourceSearch()) }

        assertTrue(exception.message!!.contains("not an empty result set"), exception.message)
        // The PDP's own wording, and a pointer at the usual cause: no `resources.<type>` candidate list.
        assertTrue(exception.message!!.contains("AuthZEN resource search failed"), exception.message)
        assertTrue(exception.message!!.contains("resources.<type>"), exception.message)
    }

    @Test
    fun `should raise rather than return a result without an identifier`() {
        server.enqueue(metadata())
        server.enqueue(json("""{"results":[{"type":"zaak","id":"1"},{"type":"zaak"}]}"""))

        val exception = assertThrows<AuthzenPdpException> { client().searchResources(resourceSearch()) }

        assertTrue(exception.message!!.contains("no identifier"), exception.message)
    }

    /**
     * OpenFTV omits a search endpoint from its metadata exactly when that API is switched off, and
     * answers the path with 501. Saying so beats relaying a 501 from a path we should not have
     * called.
     */
    @Test
    fun `should refuse a search the PDP does not advertise`() {
        server.enqueue(json("""{"access_evaluation_endpoint":"http://localhost:8443/authzen/v1/evaluation"}"""))

        val exception = assertThrows<AuthzenPdpException> { client().searchResources(resourceSearch()) }

        assertTrue(exception.message!!.contains("does not advertise a resource search endpoint"), exception.message)
        assertEquals(1, server.requestCount) // discovery only; the search was never sent
    }

    /** With no metadata to read, nothing says search is off — so it is tried on the known path. */
    @Test
    fun `should search on the OpenFTV default path when discovery fails`() {
        server.enqueue(MockResponse().setResponseCode(404))
        server.enqueue(json("""{"results":[{"id":"1"}]}"""))

        assertEquals(listOf("1"), client().searchResources(resourceSearch()))
        assertEquals(
            AuthzenEndpoints.OPEN_FTV_DEFAULT.searchResourcePath,
            takeRequestAfterDiscovery().path,
        )
    }

    @Test
    fun `should raise when a search returns an error status`() {
        server.enqueue(metadata())
        server.enqueue(MockResponse().setResponseCode(501).setBody("""{"detail":"Not Implemented"}"""))

        assertThrows<AuthzenPdpException> { client().searchResources(resourceSearch()) }
    }

    companion object {
        private const val PERMITTED_ZAAKTYPE =
            "http://localhost:8001/catalogi/api/v1/zaaktypen/744ca059-f412-49d4-8963-5800e4afd486"
    }
}
