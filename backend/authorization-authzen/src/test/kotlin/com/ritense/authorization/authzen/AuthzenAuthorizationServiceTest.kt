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

import com.ritense.authorization.Action
import com.ritense.authorization.AuthorizationContext.Companion.runWithoutAuthorization
import com.ritense.authorization.authzen.client.AuthzenPdpClient
import com.ritense.authorization.authzen.client.AuthzenPdpException
import com.ritense.authorization.authzen.client.dto.AuthzenAction
import com.ritense.authorization.authzen.client.dto.AuthzenEvaluationRequest
import com.ritense.authorization.authzen.client.dto.AuthzenResource
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.authzen.mapping.AuthzenMappingException
import com.ritense.authorization.authzen.mapping.AuthzenRequestMapper
import com.ritense.authorization.request.EntityAuthorizationRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.security.access.AccessDeniedException

class AuthzenAuthorizationServiceTest {

    private lateinit var client: AuthzenPdpClient
    private lateinit var requestMapper: AuthzenRequestMapper
    private lateinit var service: AuthzenAuthorizationService

    @BeforeEach
    fun setUp() {
        client = mock()
        requestMapper = mock()
        service = AuthzenAuthorizationService(client, requestMapper, emptyList())
    }

    private fun request(action: String = Action.VIEW) =
        EntityAuthorizationRequest(TestResource::class.java, Action<TestResource>(action), TestResource("1"))

    private fun evaluation() = AuthzenEvaluationRequest(
        subject = AuthzenSubject(type = "user", id = "alice"),
        resource = AuthzenResource(type = "test", id = "1"),
        action = AuthzenAction(name = Action.VIEW),
    )

    // ---- the bypass ----------------------------------------------------------------------------

    /**
     * The single most important test in this module. Valtimo runs 562 `runWithoutAuthorization`
     * blocks and 180 `@RunWithoutAuthorization` methods in production code; if any of them reached
     * the PDP, every internal operation would become a network round-trip.
     */
    @Test
    fun `should never consult the PDP inside runWithoutAuthorization`() {
        val permitted = runWithoutAuthorization { service.hasPermission(request()) }

        assertTrue(permitted)
        verify(client, never()).evaluate(any())
        verify(client, never()).evaluateAll(any())
        verify(requestMapper, never()).map(any())
    }

    @Test
    fun `should not throw from requirePermission inside runWithoutAuthorization`() {
        runWithoutAuthorization { service.requirePermission(request()) }

        verify(client, never()).evaluateAll(any())
    }

    /**
     * `NoopAuthorizationSpecificationFactory` is registered at `HIGHEST_PRECEDENCE` and claims every
     * request under the bypass, `Action.DENY` included. The bypass therefore wins over the DENY
     * tripwire, and this pins that ordering.
     */
    @Test
    fun `should let the bypass win over Action DENY`() {
        val permitted = runWithoutAuthorization { service.hasPermission(request(Action.DENY)) }

        assertTrue(permitted)
        verify(requestMapper, never()).map(any())
    }

    // ---- structural sentinel actions -----------------------------------------------------------

    @Test
    fun `should deny Action DENY without consulting the PDP`() {
        assertFalse(service.hasPermission(request(Action.DENY)))

        verify(requestMapper, never()).map(any())
        verify(client, never()).evaluateAll(any())
    }

    /**
     * `Action.IGNORE` means "evaluate this synthetic predicate" and carries a `Role(key = "")` that
     * is meaningless to a PDP. It is only produced by PBAC's specification machinery, which this
     * service does not provide, so reaching it is a bug — deny rather than ask.
     */
    @Test
    fun `should deny Action IGNORE without consulting the PDP`() {
        assertFalse(service.hasPermission(request(Action.IGNORE)))

        verify(requestMapper, never()).map(any())
        verify(client, never()).evaluateAll(any())
    }

    // ---- decisions -----------------------------------------------------------------------------

    @Test
    fun `should permit when the PDP permits`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation()))
        whenever(client.evaluateAll(any())).thenReturn(listOf(true))

        assertTrue(service.hasPermission(request()))
    }

    @Test
    fun `should deny when the PDP denies`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation()))
        whenever(client.evaluateAll(any())).thenReturn(listOf(false))

        assertFalse(service.hasPermission(request()))
    }

    /** Preserves PBAC's `entities.all { }` — one denied entity denies the whole request. */
    @Test
    fun `should require every entity to be permitted`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation(), evaluation(), evaluation()))
        whenever(client.evaluateAll(any())).thenReturn(listOf(true, false, true))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should permit when every entity is permitted`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation(), evaluation()))
        whenever(client.evaluateAll(any())).thenReturn(listOf(true, true))

        assertTrue(service.hasPermission(request()))
    }

    @Test
    fun `should throw AccessDeniedException from requirePermission when denied`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation()))
        whenever(client.evaluateAll(any())).thenReturn(listOf(false))

        val exception = assertThrows<AccessDeniedException> { service.requirePermission(request()) }
        assertEquals("Unauthorized", exception.message)
    }

    // ---- failure posture -----------------------------------------------------------------------

    /** No PBAC term remains to degrade to, so every failure denies. */
    @Test
    fun `should deny when the PDP cannot be reached`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation()))
        whenever(client.evaluateAll(any())).thenThrow(AuthzenPdpException("connection refused"))

        assertFalse(service.hasPermission(request()))
    }

    @Test
    fun `should deny when the request cannot be mapped`() {
        whenever(requestMapper.map(any())).thenThrow(AuthzenMappingException("no resource type configured"))

        assertFalse(service.hasPermission(request()))
    }

    // ---- the permissions overload --------------------------------------------------------------

    /**
     * The `permissions` argument is a PBAC caching artifact with no meaning to a PDP. The one
     * production call site (`ZaakDocumentService.kt:388`) must still get a real decision.
     */
    @Test
    fun `should ignore caller-supplied permissions and answer as a point check`() {
        whenever(requestMapper.map(any())).thenReturn(listOf(evaluation()))
        whenever(client.evaluateAll(any())).thenReturn(listOf(true))

        assertTrue(service.hasPermission(request(), emptyList()))
    }

    // ---- the unimplemented half ----------------------------------------------------------------

    @Test
    fun `should throw UnsupportedOperationException from getAuthorizationSpecification`() {
        val exception = assertThrows<UnsupportedOperationException> {
            service.getAuthorizationSpecification(request(), null)
        }
        assertTrue(exception.message!!.contains("getAuthorizationSpecification"))
    }

    @Test
    fun `should throw UnsupportedOperationException from getAuthorizedRoles`() {
        assertThrows<UnsupportedOperationException> { service.getAuthorizedRoles(request()) }
    }

    @Test
    fun `should throw UnsupportedOperationException from getPermissions`() {
        assertThrows<UnsupportedOperationException> {
            service.getPermissions(TestResource::class.java, Action<TestResource>(Action.VIEW))
        }
    }

    @Test
    fun `should throw UnsupportedOperationException from getMapper`() {
        assertThrows<UnsupportedOperationException> {
            service.getMapper(TestResource::class.java, TestResource::class.java)
        }
    }

    @Test
    fun `should throw UnsupportedOperationException from hasMapper`() {
        assertThrows<UnsupportedOperationException> {
            service.hasMapper(TestResource::class.java, TestResource::class.java)
        }
    }

    /**
     * `UnsupportedOperationException`, not Kotlin's `NotImplementedError`. The latter is an `Error`
     * and would sail past the broad `catch (e: Exception)` handlers these methods are called behind
     * — `PermissionResource.kt:77` among them — obscuring where the call came from.
     */
    @Test
    fun `should throw an Exception rather than an Error from unimplemented methods`() {
        val thrown = runCatching { service.getAuthorizationSpecification(request(), null) }.exceptionOrNull()

        assertTrue(thrown is Exception, "expected an Exception, got ${thrown?.javaClass?.name}")
    }

    data class TestResource(val id: String)
}
