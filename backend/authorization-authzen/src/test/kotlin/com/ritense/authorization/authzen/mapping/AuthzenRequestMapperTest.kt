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
import com.ritense.authorization.authzen.client.dto.AuthzenSubject
import com.ritense.authorization.request.EntityAuthorizationRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class AuthzenRequestMapperTest {

    private lateinit var subjectFactory: AuthzenSubjectFactory
    private lateinit var mapper: AuthzenRequestMapper

    private val subject = AuthzenSubject(type = "user", id = "alice", properties = mapOf("roles" to listOf("ROLE_USER")))

    @BeforeEach
    fun setUp() {
        subjectFactory = mock()
        whenever(subjectFactory.subjectFor(any())).thenReturn(subject)
        mapper = AuthzenRequestMapper(subjectFactory, listOf(ZaakProjection(), ContextProjection()))
    }

    @Test
    fun `should map one evaluation per entity`() {
        val request = EntityAuthorizationRequest(
            Zaak::class.java,
            Action<Zaak>(Action.VIEW),
            listOf(Zaak("1", "type-a"), Zaak("2", "type-b"), Zaak("3", "type-c")),
        )

        val evaluations = mapper.map(request)

        assertEquals(3, evaluations.size)
        assertEquals(listOf("1", "2", "3"), evaluations.map { it.resource.id })
    }

    /**
     * An empty entity list is a type-level question — "may I create one at all?" — not a question
     * about zero things. PBAC evaluates it as a single check against a null entity
     * (`entities.ifEmpty { listOf(null) }`); the PDP additionally rejects a resource with no id,
     * so it becomes one evaluation carrying the wildcard.
     */
    @Test
    fun `should map an empty entity list to a single wildcard evaluation`() {
        val request = EntityAuthorizationRequest(Zaak::class.java, Action<Zaak>(Action.CREATE), emptyList())

        val evaluations = mapper.map(request)

        assertEquals(1, evaluations.size)
        assertEquals(AuthzenRequestMapper.ANY_RESOURCE_ID, evaluations.single().resource.id)
    }

    @Test
    fun `should use the wildcard id when a projection has no identifier`() {
        val request = EntityAuthorizationRequest(Zaak::class.java, Action<Zaak>(Action.VIEW), Zaak(null, "type-a"))

        assertEquals(AuthzenRequestMapper.ANY_RESOURCE_ID, mapper.map(request).single().resource.id)
    }

    @Test
    fun `should carry the action key as the action name`() {
        val request = EntityAuthorizationRequest(Zaak::class.java, Action<Zaak>(Action.MODIFY), Zaak("1", "type-a"))

        assertEquals(Action.MODIFY, mapper.map(request).single().action.name)
    }

    @Test
    fun `should omit the context entirely when the request carries none`() {
        val request = EntityAuthorizationRequest(Zaak::class.java, Action<Zaak>(Action.VIEW), Zaak("1", "type-a"))

        assertNull(mapper.map(request).single().context)
    }

    // ---- failures, all of which deny -----------------------------------------------------------

    @Test
    fun `should refuse to map when no subject can be established`() {
        whenever(subjectFactory.subjectFor(any())).thenReturn(null)
        val request = EntityAuthorizationRequest(Zaak::class.java, Action<Zaak>(Action.VIEW), Zaak("1", "type-a"))

        assertThrows<AuthzenMappingException> { mapper.map(request) }
    }

    data class Zaak(val id: String?, val zaaktype: String)
    data class ContextResource(val id: String)

    private class ZaakProjection : AuthzenResourceProperties<Zaak> {
        override val resourceType = Zaak::class.java
        override fun idOf(entity: Zaak) = entity.id
        override fun propertiesOf(entity: Zaak) = mapOf<String, Any?>("zaaktype" to entity.zaaktype)
    }

    private class ContextProjection : AuthzenResourceProperties<ContextResource> {
        override val resourceType = ContextResource::class.java
        override fun idOf(entity: ContextResource) = entity.id
        override fun propertiesOf(entity: ContextResource) = emptyMap<String, Any?>()
    }
}
