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

import com.ritense.authorization.Action
import com.ritense.authorization.authzen.AuthzenProperties
import com.ritense.authorization.request.DelegateUserEntityAuthorizationRequest
import com.ritense.authorization.request.EntityAuthorizationRequest
import com.ritense.valtimo.contract.authentication.ManageableUser
import com.ritense.valtimo.contract.authentication.UserManagementService
import com.ritense.valtimo.contract.authentication.model.ValtimoUserBuilder
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder

class AuthzenSubjectFactoryTest {

    private lateinit var userManagementService: UserManagementService
    private lateinit var factory: AuthzenSubjectFactory

    @BeforeEach
    fun setUp() {
        userManagementService = mock()
        factory = AuthzenSubjectFactory(userManagementService, AuthzenProperties())
    }

    @AfterEach
    fun tearDown() {
        SecurityContextHolder.clearContext()
    }

    private fun authenticateAs(login: String, vararg roles: String) {
        SecurityContextHolder.getContext().authentication = UsernamePasswordAuthenticationToken(
            login,
            "n/a",
            roles.map { SimpleGrantedAuthority(it) },
        )
    }

    private fun request() =
        EntityAuthorizationRequest(TestResource::class.java, Action<TestResource>(Action.VIEW), TestResource("1"))

    private fun delegateRequest(username: String) = DelegateUserEntityAuthorizationRequest(
        TestResource::class.java,
        Action<TestResource>(Action.ASSIGNABLE),
        username,
        TestResource("1"),
    )

    @Test
    fun `should build a subject from the authenticated user`() {
        authenticateAs("alice", "ROLE_USER", "ROLE_ADMIN")

        val subject = factory.subjectFor(request())!!

        assertEquals("user", subject.type)
        assertEquals("alice", subject.id)
        assertEquals(listOf("ROLE_USER", "ROLE_ADMIN"), subject.properties?.get(AuthzenSubjectFactory.ROLES))
    }

    /**
     * Mirrors `ValtimoAuthorizationService.getPermissions`, which resolves no roles and therefore
     * denies when there is no user. A null subject is a denial.
     */
    @Test
    fun `should return no subject when nobody is authenticated`() {
        assertNull(factory.subjectFor(request()))
    }

    /**
     * Several `UserManagementService` implementations throw `NotImplementedException` rather than
     * answering. A policy referencing a property we could not resolve should deny — which is what
     * an absent property already does — so the failure must be dropped, never fatal.
     */
    @Test
    fun `should build a subject even when optional user properties are unavailable`() {
        authenticateAs("alice", "ROLE_USER")
        whenever(userManagementService.currentUser).thenThrow(NotImplementedError("not implemented"))
        whenever(userManagementService.currentUserTeams).thenThrow(NotImplementedError("not implemented"))

        val subject = factory.subjectFor(request())!!

        assertEquals("alice", subject.id)
        assertEquals(listOf("ROLE_USER"), subject.properties?.get(AuthzenSubjectFactory.ROLES))
        assertNull(subject.properties?.get(AuthzenSubjectFactory.EMAIL))
    }

    // ---- delegate requests -----------------------------------------------------------------------

    /**
     * A `DelegateUserEntityAuthorizationRequest` asks "would *this other user* be allowed?" — used
     * to build assignee candidate lists. Sending the caller's roles would answer a different
     * question entirely.
     */
    @Test
    fun `should resolve the delegate's roles rather than the caller's`() {
        authenticateAs("alice", "ROLE_ADMIN")
        whenever(userManagementService.findByUsername("bob")).thenReturn(
            user(id = "bob-id", username = "bob", email = "bob@example.com", roles = listOf("ROLE_USER"))
        )

        val subject = factory.subjectFor(delegateRequest("bob"))!!

        assertEquals("bob", subject.id)
        assertEquals(listOf("ROLE_USER"), subject.properties?.get(AuthzenSubjectFactory.ROLES))
        assertEquals("bob@example.com", subject.properties?.get(AuthzenSubjectFactory.EMAIL))
    }

    @Test
    fun `should return no subject when the delegate user is unknown`() {
        authenticateAs("alice", "ROLE_ADMIN")
        whenever(userManagementService.findByUsername("ghost")).thenReturn(null)

        assertNull(factory.subjectFor(delegateRequest("ghost")))
    }

    @Test
    fun `should return no subject when resolving the delegate user fails`() {
        authenticateAs("alice", "ROLE_ADMIN")
        whenever(userManagementService.findByUsername("bob")).thenThrow(RuntimeException("identity provider down"))

        assertNull(factory.subjectFor(delegateRequest("bob")))
    }

    /** A real [ValtimoUser] rather than a mock — it is the production implementation and needs no stubbing. */
    private fun user(id: String, username: String, email: String, roles: List<String>): ManageableUser =
        ValtimoUserBuilder()
            .id(id)
            .username(username)
            .email(email)
            .firstName(username)
            .lastName("Example")
            .roles(roles)
            .build()

    data class TestResource(val id: String)
}
