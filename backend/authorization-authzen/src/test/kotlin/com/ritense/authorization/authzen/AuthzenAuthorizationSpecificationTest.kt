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
import com.ritense.authorization.request.EntityAuthorizationRequest
import com.ritense.authorization.specification.AuthorizationSpecification
import jakarta.persistence.criteria.AbstractQuery
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.CriteriaQuery
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class AuthzenAuthorizationSpecificationTest {

    private val root: Root<TestResource> = mock()
    private val query: CriteriaQuery<*>? = mock<CriteriaQuery<*>>()
    private val criteriaBuilder: CriteriaBuilder = mock()
    private val innerPredicate: Predicate = mock()
    private val falsePredicate: Predicate = mock()
    private val inner: AuthorizationSpecification<TestResource> = mock()

    private fun specification(decision: Boolean): AuthzenAuthorizationSpecification<TestResource> {
        whenever(inner.toPredicate(any(), any<AbstractQuery<*>>(), any())).thenReturn(innerPredicate)
        whenever(criteriaBuilder.disjunction()).thenReturn(falsePredicate)
        return AuthzenAuthorizationSpecification(
            decision,
            inner,
            EntityAuthorizationRequest(TestResource::class.java, Action(Action.VIEW)),
            { emptyList() },
        )
    }

    @Test
    fun `should filter the query with the inner specification when the PDP permits`() {
        assertSame(innerPredicate, specification(decision = true).toPredicate(root, query, criteriaBuilder))
    }

    @Test
    fun `should filter out every row when the PDP denies`() {
        assertSame(falsePredicate, specification(decision = false).toPredicate(root, query, criteriaBuilder))

        verify(inner, never()).toPredicate(any(), any<AbstractQuery<*>>(), any())
    }

    data class TestResource(val id: String)
}
