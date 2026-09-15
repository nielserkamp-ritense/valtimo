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

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.ritense.authorization.Action
import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.authzen.client.AuthzenPdpClient
import com.ritense.authorization.authzen.client.AuthzenPdpException
import com.ritense.authorization.authzen.client.dto.AuthzenAction
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenResourceSearchRequest
import com.ritense.authorization.authzen.client.dto.AuthzenSearchResource
import com.ritense.authorization.authzen.client.dto.AuthzenSearchSubject
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.authzen.client.dto.AuthzenSubjectSearchRequest
import com.ritense.authorization.authzen.mapping.AuthzenRequestMapper
import com.ritense.authorization.authzen.mapping.AuthzenResourceProperties
import com.ritense.authorization.authzen.mapping.AuthzenResourceTypeRegistry
import com.ritense.authorization.authzen.mapping.AuthzenSubjectFactory
import com.ritense.authorization.request.EntityAuthorizationRequest
import com.ritense.valtimo.contract.authentication.UserManagementService
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.reactive.function.client.WebClient
import java.net.HttpURLConnection
import java.net.URI
import java.time.Duration

/**
 * Exercises the whole chain — service, mapper, client — against a **real** AuthZEN PDP loaded with
 * the hand-written Cedar policies in `pdp/policies/` at the repository root.
 *
 * These assertions are the translation contract: each one restates a rule from the
 * `*.permission.json` its Cedar policy was translated from, so a policy edit that changes meaning
 * fails here rather than in someone's browser.
 *
 * Start the PDP from the repository root, then run the tagged suite:
 * ```
 * docker compose up -d pdp
 * ./gradlew :backend:authorization-authzen:integrationTestingPostgresql
 * ```
 * With no PDP answering, every test skips — a build without one is unaffected.
 */
@Tag("integration")
class AuthzenPdpLiveIT {

    private lateinit var service: AuthzenAuthorizationService
    private lateinit var client: AuthzenPdpClient

    @BeforeEach
    fun setUp() {
        assumeTrue(pdpIsReachable(), "No AuthZEN PDP at $PDP_URL; skipping. Run `docker compose up -d pdp`.")

        val properties = AuthzenProperties(
            enabled = true,
            url = PDP_URL,
            timeout = Duration.ofSeconds(5),
            resourceTypes = mapOf(
                TestObject::class.java.name to AuthzenProperties.ResourceTypeProperties("object"),
                TestZaak::class.java.name to AuthzenProperties.ResourceTypeProperties("zaak"),
                TestManagedUser::class.java.name to AuthzenProperties.ResourceTypeProperties("managed_user"),
            ),
        )
        val objectMapper = ObjectMapper().registerKotlinModule()
        client = AuthzenPdpClient(WebClient.builder().build(), objectMapper, properties)
        val userManagementService: UserManagementService = mock()
        val mapper = AuthzenRequestMapper(
            AuthzenResourceTypeRegistry(properties),
            AuthzenSubjectFactory(userManagementService, properties),
            listOf(ObjectProjection(), ZaakProjection(), ManagedUserProjection()),
        )
        service = AuthzenAuthorizationService(client, mapper, emptyList())
    }

    @AfterEach
    fun tearDown() = SecurityContextHolder.clearContext()

    private fun authenticateAs(login: String, vararg roles: String) {
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken(login, "n/a", roles.map { SimpleGrantedAuthority(it) })
    }

    // ---- object: object-role-user-read.cedar / object-role-admin-all.cedar ----------------------

    @Test
    fun `should let ROLE_USER read objects but not write them`() {
        authenticateAs("alice", ROLE_USER)

        assertTrue(service.hasPermission(objectRequest(Action.VIEW)))
        assertTrue(service.hasPermission(objectRequest(Action.VIEW_LIST)))
        assertFalse(service.hasPermission(objectRequest(Action.CREATE)))
        assertFalse(service.hasPermission(objectRequest(Action.MODIFY)))
        assertFalse(service.hasPermission(objectRequest(Action.DELETE)))
    }

    @Test
    fun `should let ROLE_ADMIN do everything to objects`() {
        authenticateAs("root", ROLE_ADMIN)

        listOf(Action.VIEW, Action.VIEW_LIST, Action.CREATE, Action.MODIFY, Action.DELETE).forEach { action ->
            assertTrue(service.hasPermission(objectRequest(action)), "ROLE_ADMIN should be allowed to $action")
        }
    }

    @Test
    fun `should deny a user holding neither role`() {
        authenticateAs("nobody", "ROLE_GUEST")

        assertFalse(service.hasPermission(objectRequest(Action.VIEW)))
    }

    // ---- zaak: zaak-role-admin-view.cedar -------------------------------------------------------

    /** The `field ==` condition on `zaaktype` in `zaken.permission.json`, as a resource property. */
    @Test
    fun `should let ROLE_ADMIN view only the permitted zaaktype`() {
        authenticateAs("root", ROLE_ADMIN)

        assertTrue(service.hasPermission(zaakRequest(PERMITTED_ZAAKTYPE)))
        assertFalse(service.hasPermission(zaakRequest("http://localhost:8001/catalogi/api/v1/zaaktypen/other")))
    }

    @Test
    fun `should deny ROLE_USER any zaak, since no policy grants one`() {
        authenticateAs("alice", ROLE_USER)

        assertFalse(service.hasPermission(zaakRequest(PERMITTED_ZAAKTYPE)))
    }

    // ---- managed_user: managed-user-role-*-view.cedar --------------------------------------------

    /**
     * The `list_contains` condition in `user.permission.json` is on the *resource's* roles: a
     * ROLE_USER may see other ROLE_USERs, but not administrators.
     */
    @Test
    fun `should let ROLE_USER see only other users holding ROLE_USER`() {
        authenticateAs("alice", ROLE_USER)

        assertTrue(service.hasPermission(managedUserRequest(listOf(ROLE_USER))))
        assertFalse(service.hasPermission(managedUserRequest(listOf(ROLE_ADMIN))))
    }

    @Test
    fun `should let ROLE_ADMIN see any user`() {
        authenticateAs("root", ROLE_ADMIN)

        assertTrue(service.hasPermission(managedUserRequest(listOf(ROLE_USER))))
        assertTrue(service.hasPermission(managedUserRequest(listOf(ROLE_ADMIN))))
    }

    // ---- multi-entity batching -------------------------------------------------------------------

    /** N entities become one `/evaluations` call, and every one of them has to pass. */
    @Test
    fun `should require every entity in a batch to be permitted`() {
        authenticateAs("alice", ROLE_USER)

        val allVisible = EntityAuthorizationRequest(
            TestManagedUser::class.java,
            Action<TestManagedUser>(Action.VIEW),
            listOf(TestManagedUser("a", listOf(ROLE_USER)), TestManagedUser("b", listOf(ROLE_USER))),
        )
        val oneHidden = EntityAuthorizationRequest(
            TestManagedUser::class.java,
            Action<TestManagedUser>(Action.VIEW),
            listOf(TestManagedUser("a", listOf(ROLE_USER)), TestManagedUser("b", listOf(ROLE_ADMIN))),
        )

        assertTrue(service.hasPermission(allVisible))
        assertFalse(service.hasPermission(oneHidden))
    }

    /** Comfortably past the point where the client has to chunk by body size. */
    @Test
    fun `should evaluate a large batch correctly across chunks`() {
        authenticateAs("alice", ROLE_USER)

        val entities = (1..400).map { TestManagedUser("user-$it", listOf(ROLE_USER)) }
        val request = EntityAuthorizationRequest(
            TestManagedUser::class.java,
            Action<TestManagedUser>(Action.VIEW),
            entities,
        )

        assertTrue(service.hasPermission(request))
    }

    // ---- behaviour that must survive contact with a real PDP -------------------------------------

    @Test
    fun `should not consult a reachable PDP inside runWithoutAuthorization`() {
        authenticateAs("nobody", "ROLE_GUEST")

        // ROLE_GUEST is denied by every policy, so a permit here can only come from the bypass.
        assertTrue(runWithoutAuthorization { service.hasPermission(objectRequest(Action.VIEW)) })
    }

    /**
     * The PDP rejects an evaluation whose resource has no id with `400 invalid resource`. A
     * type-level question ("may I create one at all?") legitimately has no instance, so the mapper
     * sends `*` — and this asserts the PDP accepts it rather than erroring, which would surface as
     * a blanket denial.
     */
    @Test
    fun `should answer a type-level request that carries no entity`() {
        authenticateAs("root", ROLE_ADMIN)

        val request = EntityAuthorizationRequest(
            TestObject::class.java,
            Action<TestObject>(Action.CREATE),
            emptyList(),
        )

        assertTrue(service.hasPermission(request))
    }

    /** Metadata discovery has to yield OpenFTV's `/authzen/v1` paths, not the specification's. */
    @Test
    fun `should discover the endpoints OpenFTV actually serves`() {
        authenticateAs("root", ROLE_ADMIN)

        // A successful decision proves the discovered path was right; a wrong path would 404.
        assertTrue(service.hasPermission(objectRequest(Action.VIEW)))
    }

    // ---- search -----------------------------------------------------------------------------------

    /**
     * A subject search answers from the `subjects.user` candidate list in
     * `pdp/pip/attributes/search-candidates.yaml` — the PDP has no other source of subjects.
     *
     * The answer is all-or-nothing for any policy that reads `principal.roles`: the PDP gives
     * **every** candidate the properties from the request's subject (`search.go:26-33`), so these
     * three ids are evaluated with the *requester's* roles rather than their own. It enumerates
     * candidates; it does not know anything about them.
     */
    @Test
    fun `should return the subject candidate list the PDP was given`() {
        val request = AuthzenSubjectSearchRequest(
            subject = AuthzenSearchSubject(type = "user", properties = mapOf("roles" to listOf(ROLE_USER))),
            resource = AuthzenResource(type = "object", id = AuthzenRequestMapper.ANY_RESOURCE_ID),
            action = AuthzenAction(name = Action.VIEW),
        )

        assertEquals(listOf("root", "alice", "nobody"), client.searchSubjects(request))
    }

    /**
     * The PDP's search endpoints are reachable, and a search for a type with no candidate list fails
     * *loudly*.
     *
     * The PDP enumerates one PIP attribute — `resources.zaak`, a comma-separated string of candidate
     * ids — and `pdp/policies/` ships none, so the search cannot run. It says so with **HTTP 200 and
     * an error body**, and the client's job is to raise rather than report "no zaken are allowed".
     *
     * Reaching that message also proves discovery found the search path: a wrong path would 404 with
     * a different one. Should a candidate list ever be configured, this becomes an assertion on the
     * ids returned.
     */
    @Test
    fun `should raise rather than read a failed resource search as an empty result`() {
        val request = AuthzenResourceSearchRequest(
            subject = AuthzenSubject(type = "user", id = "root"),
            resource = AuthzenSearchResource(type = "zaak"),
            action = AuthzenAction(name = Action.VIEW),
        )

        val exception = assertThrows<AuthzenPdpException> { client.searchResources(request) }

        assertTrue(
            exception.message!!.contains("not an empty result set"),
            "Expected the missing-results failure, got: ${exception.message}",
        )
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    private fun objectRequest(action: String) =
        EntityAuthorizationRequest(TestObject::class.java, Action<TestObject>(action), TestObject())

    private fun zaakRequest(zaaktype: String) =
        EntityAuthorizationRequest(TestZaak::class.java, Action<TestZaak>(Action.VIEW), TestZaak(zaaktype))

    private fun managedUserRequest(roles: List<String>) = EntityAuthorizationRequest(
        TestManagedUser::class.java,
        Action<TestManagedUser>(Action.VIEW),
        TestManagedUser("target", roles),
    )

    class TestObject
    data class TestZaak(val zaaktype: String)
    data class TestManagedUser(val username: String, val roles: List<String>)

    private class ObjectProjection : AuthzenResourceProperties<TestObject> {
        override val resourceType = TestObject::class.java
        override fun idOf(entity: TestObject): String? = null
        override fun propertiesOf(entity: TestObject) = emptyMap<String, Any?>()
    }

    private class ZaakProjection : AuthzenResourceProperties<TestZaak> {
        override val resourceType = TestZaak::class.java
        override fun idOf(entity: TestZaak): String? = null
        override fun propertiesOf(entity: TestZaak) = mapOf<String, Any?>("zaaktype" to entity.zaaktype)
    }

    private class ManagedUserProjection : AuthzenResourceProperties<TestManagedUser> {
        override val resourceType = TestManagedUser::class.java
        override fun idOf(entity: TestManagedUser) = entity.username
        override fun propertiesOf(entity: TestManagedUser) = mapOf<String, Any?>("roles" to entity.roles)
    }

    companion object {
        private const val ROLE_USER = "ROLE_USER"
        private const val ROLE_ADMIN = "ROLE_ADMIN"

        private const val PERMITTED_ZAAKTYPE =
            "http://localhost:8001/catalogi/api/v1/zaaktypen/744ca059-f412-49d4-8963-5800e4afd486"

        private val PDP_URL: String = System.getenv("VALTIMO_AUTHZEN_URL") ?: "http://localhost:8443"

        private var reachable: Boolean? = null

        @JvmStatic
        @BeforeAll
        fun probeOnce() {
            reachable = pdpIsReachable()
        }

        private fun pdpIsReachable(): Boolean = reachable ?: try {
            val connection = URI("$PDP_URL/.well-known/authzen-configuration").toURL()
                .openConnection() as HttpURLConnection
            connection.connectTimeout = 1000
            connection.readTimeout = 1000
            connection.requestMethod = "GET"
            connection.responseCode in 200..499
        } catch (e: Exception) {
            false
        }
    }
}
