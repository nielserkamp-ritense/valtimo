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

import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.ritense.authorization.Action
import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.authzen.client.AuthzenPdpClient
import com.ritense.authorization.authzen.client.AuthzenPdpException
import com.ritense.authorization.authzen.client.dto.AuthzenAction
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationRequest
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationResponseTyped
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.authzen.mapping.AuthzenMappingException
import com.ritense.authorization.authzen.mapping.AuthzenRequestMapper
import com.ritense.authorization.permission.ConditionContainer
import com.ritense.authorization.permission.Permission
import com.ritense.authorization.request.AuthorizationRequest
import com.ritense.authorization.request.EntityAuthorizationRequest
import com.ritense.authorization.role.Role
import com.ritense.authorization.specification.AuthorizationSpecification
import com.ritense.authorization.specification.AuthorizationSpecificationFactory
import com.ritense.authorization.specification.impl.DenyAuthorizationSpecificationFactory
import com.ritense.authorization.specification.impl.NoopAuthorizationSpecificationFactory
import com.ritense.valtimo.contract.authentication.ManageableUser
import com.ritense.valtimo.contract.authentication.UserManagementService
import jakarta.persistence.criteria.AbstractQuery
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder

class AuthzenAuthorizationServiceTest {

    private val objectMapper = jacksonObjectMapper()
    private lateinit var client: AuthzenPdpClient
    private lateinit var requestMapper: AuthzenRequestMapper
    private lateinit var userManagementService: UserManagementService
    private lateinit var service: AuthzenAuthorizationService

    @BeforeEach
    fun setUp() {
        client = mock()
        requestMapper = mock()
        userManagementService = mock()
        service = AuthzenAuthorizationService(
            authorizationSpecificationFactories = listOf(
                NoopAuthorizationSpecificationFactory<Any>(),
                DenyAuthorizationSpecificationFactory<Any>(),
                TestSpecificationFactory(),
            ),
            mappers = emptyList(),
            client = client,
            requestMapper = requestMapper,
            actionProviders = emptyList(),
            userManagementService = userManagementService,
            objectMapper = objectMapper,
        )
        SecurityContextHolder.getContext().authentication = UsernamePasswordAuthenticationToken(
            "alice", null, listOf(SimpleGrantedAuthority(USER_ROLE))
        )
    }

    @AfterEach
    fun tearDown() = SecurityContextHolder.clearContext()

    // ---- PDP decisions -------------------------------------------------------------------------

    @Test
    fun `should permit when the PDP permits and publishes a permission for the user's role`() {
        givenPdpAnswers(decision = true, filter = listOf(permissionNode(role = USER_ROLE)))

        assertTrue(service.hasPermission(request()))
    }

    @Test
    fun `should deny when the PDP denies`() {
        givenPdpAnswers(decision = false, filter = listOf(permissionNode(role = USER_ROLE)))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should deny when the published permission belongs to another role`() {
        givenPdpAnswers(decision = true, filter = listOf(permissionNode(role = "ROLE_OTHER")))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should throw AccessDeniedException from requirePermission when denied`() {
        givenPdpAnswers(decision = false, filter = emptyList())

        val exception = assertThrows<AccessDeniedException> { service.requirePermission(request()) }
        assertEquals("Unauthorized", exception.message)
    }

    /** Preserves PBAC's `entities.all { }`: one denied entity denies the whole request. */
    @Test
    fun `should require every entity to be permitted`() {
        givenPdpAnswers(listOf(true, false), filter = listOf(permissionNode(role = USER_ROLE)))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should permit when every entity is permitted`() {
        givenPdpAnswers(listOf(true, true), filter = listOf(permissionNode(role = USER_ROLE)))

        assertTrue(service.hasPermission(request()))
    }

    // ---- failure posture -----------------------------------------------------------------------

    @Test
    fun `should deny when the PDP cannot be reached`() {
        givenPdpAnswers(decision = true, filter = emptyList())
        whenever(client.evaluateAllWithResponseType(any(), eq(ObjectNode::class.java)))
            .thenThrow(AuthzenPdpException("connection refused"))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should deny when the request cannot be mapped`() {
        whenever(requestMapper.map(any<AuthorizationRequest<*>>())).thenThrow(AuthzenMappingException("no subject"))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should return no permissions when the PDP cannot be reached`() {
        givenPdpAnswers(decision = true, filter = emptyList())
        whenever(client.evaluateAllWithResponseType(any(), eq(ObjectNode::class.java)))
            .thenThrow(AuthzenPdpException("connection refused"))

        assertTrue(service.getPermissions(TestResource::class.java, Action<TestResource>(Action.VIEW)).isEmpty())
    }

    @Test
    fun `should ignore unknown permissions in the PDP filter`() {
        val unknown = objectMapper.createObjectNode().put("type", "SomethingElse")
        givenPdpAnswers(decision = true, filter = listOf(unknown, permissionNode(role = USER_ROLE)))

        assertTrue(service.hasPermission(request()))
    }

    @Test
    fun `should ignore a ZaakTypePermission on a resource type it does not apply to`() {
        val zaakType = objectMapper.createObjectNode().apply {
            put("type", "ZaakTypePermission")
            put("role", USER_ROLE)
            putArray("urls").add("http://zaaktype/1")
        }
        givenPdpAnswers(decision = true, filter = listOf(zaakType))

        assertTrue(service.getPermissions(TestResource::class.java, Action<TestResource>(Action.VIEW)).isEmpty())
    }

    // ---- the permissions overload --------------------------------------------------------------

    /** `ZaakDocumentService` passes permissions it got from [AuthzenAuthorizationService.getPermissions]. */
    @Test
    fun `should decide hasPermission with caller-supplied permissions locally`() {
        assertTrue(service.hasPermission(request(), listOf(permission(Action.VIEW))))
        assertFalse(service.hasPermission(request(), emptyList()))

        verifyPdpNeverConsulted()
    }

    // ---- permission resolution -----------------------------------------------------------------

    /** Logging and the specification both read the permissions; the delegate is resolved once. */
    @Test
    fun `should resolve the permissions of a request once`() {
        val user: ManageableUser = mock()
        whenever(user.roles).thenReturn(listOf(USER_ROLE))
        whenever(userManagementService.findByUsername("bob")).thenReturn(user)
        givenPdpAnswers(decision = true, filter = listOf(permissionNode(role = USER_ROLE)))

        val delegateRequest = object : EntityAuthorizationRequest<TestResource>(
            TestResource::class.java, Action(Action.VIEW), listOf(TestResource("1"))
        ) {
            override val user = "bob"
        }

        assertTrue(service.hasPermission(delegateRequest))
        verify(userManagementService, times(1)).findByUsername("bob")
    }

    // ---- requests the PDP must not answer ------------------------------------------------------

    /**
     * PBAC's nested evaluation (`ContainerPermissionCondition.findChildSpecification`,
     * `AuthorizationSpecification.findSpecification`) passes its own permissions. Those decide alone,
     * exactly as in `ValtimoAuthorizationService`.
     */
    @Test
    fun `should decide caller-supplied permissions locally without consulting the PDP`() {
        val permitted = service.getAuthorizationSpecification(request(Action.IGNORE), listOf(permission(Action.IGNORE)))
            .isAuthorized()

        assertTrue(permitted)
        verifyPdpNeverConsulted()
    }

    @Test
    fun `should deny empty caller-supplied permissions without consulting the PDP`() {
        val permitted = service.getAuthorizationSpecification(request(), emptyList()).isAuthorized()

        assertFalse(permitted)
        verifyPdpNeverConsulted()
    }

    @Test
    fun `should not consult the PDP from getAuthorizationSpecification inside runWithoutAuthorization`() {
        val permitted = runWithoutAuthorization { service.getAuthorizationSpecification(request(), null).isAuthorized() }

        assertTrue(permitted)
        verifyPdpNeverConsulted()
    }

    @Test
    fun `should not consult the PDP from hasPermission inside runWithoutAuthorization`() {
        val permitted = runWithoutAuthorization { service.hasPermission(request()) }

        assertTrue(permitted)
        verifyPdpNeverConsulted()
    }

    @Test
    fun `should deny Action IGNORE without permissions and without consulting the PDP`() {
        assertFalse(service.getAuthorizationSpecification(request(Action.IGNORE), null).isAuthorized())

        verifyPdpNeverConsulted()
    }

    @Test
    fun `should deny Action DENY without consulting the PDP`() {
        assertFalse(service.hasPermission(request(Action.DENY)))

        verifyPdpNeverConsulted()
    }

    // ---- permission mapping --------------------------------------------------------------------

    @Test
    fun `should keep the context restriction of a published permission`() {
        givenPdpAnswers(
            decision = true,
            filter = listOf(
                permissionNode(role = USER_ROLE).apply {
                    put("contextResourceType", ContextResource::class.java.name)
                    set<ObjectNode>("contextConditionContainer", objectMapper.createObjectNode().apply { putArray("conditions") })
                }
            )
        )

        val permission = service.getPermissions(TestResource::class.java, Action<TestResource>(Action.VIEW)).single()

        assertEquals(ContextResource::class.java, permission.contextResourceType)
        assertEquals(ConditionContainer(emptyList()), permission.contextConditionContainer)
    }

    @Test
    fun `should leave the context empty when a published permission has none`() {
        givenPdpAnswers(decision = true, filter = listOf(permissionNode(role = USER_ROLE)))

        val permission = service.getPermissions(TestResource::class.java, Action<TestResource>(Action.VIEW)).single()

        assertNull(permission.contextResourceType)
        assertNull(permission.contextConditionContainer)
    }

    // ---- helpers -------------------------------------------------------------------------------

    private fun request(action: String = Action.VIEW) =
        EntityAuthorizationRequest(TestResource::class.java, Action<TestResource>(action), TestResource("1"))

    private fun permission(action: String) = Permission(
        resourceType = TestResource::class.java,
        actions = mutableListOf(Action<Any>(action)),
        conditionContainer = ConditionContainer(emptyList()),
        role = Role(key = USER_ROLE),
    )

    private fun permissionNode(role: String): ObjectNode = objectMapper.createObjectNode().apply {
        put("type", "ValtimoAuthorizationPermission")
        put("resourceType", TestResource::class.java.name)
        putArray("actions").add(Action.VIEW)
        set<ObjectNode>("conditionContainer", objectMapper.createObjectNode().apply { putArray("conditions") })
        put("role", role)
    }

    private fun givenPdpAnswers(decision: Boolean, filter: List<ObjectNode>) =
        givenPdpAnswers(listOf(decision), filter)

    private fun givenPdpAnswers(decisions: List<Boolean>, filter: List<ObjectNode>) {
        val evaluation = AuthzenEvaluationRequest(
            subject = AuthzenSubject(type = "user", id = "alice"),
            resource = AuthzenResource(type = TestResource::class.java.name, id = "1"),
            action = AuthzenAction(name = Action.VIEW),
        )
        whenever(requestMapper.map(any<AuthorizationRequest<*>>())).thenReturn(decisions.map { evaluation })
        whenever(requestMapper.map(any<Class<*>>(), any())).thenReturn(listOf(evaluation))

        val context = objectMapper.createObjectNode().apply { putArray("filter").addAll(filter) }
        whenever(client.evaluateAllWithResponseType(any(), eq(ObjectNode::class.java)))
            .thenReturn(decisions.map { AuthzenEvaluationResponseTyped(decision = it, context = context) })
    }

    private fun verifyPdpNeverConsulted() {
        verify(requestMapper, never()).map(any<AuthorizationRequest<*>>())
        verify(client, never()).evaluateAllWithResponseType(any(), any<Class<*>>())
    }

    data class TestResource(val id: String)

    class ContextResource

    private class TestSpecificationFactory : AuthorizationSpecificationFactory<TestResource> {
        override fun canCreate(request: AuthorizationRequest<*>, permissionSupplier: () -> List<Permission>) =
            request.resourceType == TestResource::class.java

        override fun create(
            request: AuthorizationRequest<TestResource>,
            permissionSupplier: () -> List<Permission>,
        ): AuthorizationSpecification<TestResource> = TestSpecification(request, permissionSupplier)
    }

    private class TestSpecification(
        request: AuthorizationRequest<TestResource>,
        permissionSupplier: () -> List<Permission>,
    ) : AuthorizationSpecification<TestResource>(request, permissionSupplier) {
        override fun identifierToEntity(identifier: String) = TestResource(identifier)

        override fun toPredicate(
            root: Root<TestResource>,
            query: AbstractQuery<*>,
            criteriaBuilder: CriteriaBuilder,
        ): Predicate = throw UnsupportedOperationException()
    }

    companion object {
        private const val USER_ROLE = "ROLE_USER"
    }
}
