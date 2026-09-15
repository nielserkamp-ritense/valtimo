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

package com.ritense.authorization.authzen.autoconfigure

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.ritense.authorization.AuthorizationService
import com.ritense.authorization.AuthorizationServiceHolder
import com.ritense.authorization.authzen.AuthzenAuthorizationService
import com.ritense.authorization.authzen.mapping.AuthzenResourceProperties
import com.ritense.authorization.autoconfigure.AuthorizationAutoConfiguration
import com.ritense.valtimo.contract.authentication.UserManagementService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

class AuthzenAuthorizationAutoConfigurationTest {

    private val resourceType = ProjectedResource::class.java.name

    private val runner = ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AuthzenAuthorizationAutoConfiguration::class.java))
        .withUserConfiguration(SupportingBeans::class.java)

    /**
     * The default in every existing application. Nothing is contributed, so Valtimo keeps using its
     * own PBAC implementation and behaves exactly as it does today.
     */
    @Test
    fun `should contribute no beans when disabled`() {
        runner.run { context ->
            assertTrue(context.getBeanNamesForType(AuthzenAuthorizationService::class.java).isEmpty())
            assertTrue(context.getBeanNamesForType(AuthorizationService::class.java).isEmpty())
        }
    }

    @Test
    fun `should contribute no beans when the flag is absent entirely`() {
        runner.withPropertyValues("valtimo.authorization.authzen.url=http://pdp:8443").run { context ->
            assertTrue(context.getBeanNamesForType(AuthzenAuthorizationService::class.java).isEmpty())
        }
    }

    @Test
    fun `should register the AuthZEN service as the AuthorizationService when enabled`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.enabled=true",
                "valtimo.authorization.authzen.resource-types[$resourceType].name=projected",
            )
            .run { context ->
                assertTrue(context.getBean(AuthorizationService::class.java) is AuthzenAuthorizationService)
            }
    }

    /**
     * The holder is normally populated as a side effect inside the very bean method this module
     * suppresses (`AuthorizationAutoConfiguration.kt:104`), and `currentInstance` dereferences a
     * nullable field with `!!`. Leaving it null turns the first static, re-entrant lookup into a
     * `NullPointerException` far from its cause.
     */
    @Test
    fun `should populate the static AuthorizationServiceHolder`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.enabled=true",
                "valtimo.authorization.authzen.resource-types[$resourceType].name=projected",
            )
            .run { context ->
                val service = context.getBean(AuthzenAuthorizationService::class.java)
                assertEquals(service, AuthorizationServiceHolder.currentInstance)
            }
    }

    /**
     * Without a projection the PDP receives no attributes for the type, and a Cedar condition on an
     * absent attribute is simply false — the type would deny every conditional policy while looking
     * perfectly healthy. Failing at startup is the only place this is cheap to notice.
     */
    @Test
    fun `should fail startup when a configured resource type has no projection`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.enabled=true",
                "valtimo.authorization.authzen.resource-types[com.example.Unprojected].name=unprojected",
            )
            .run { context ->
                assertTrue(context.startupFailure != null, "expected the context to fail to start")
                assertTrue(
                    context.startupFailure!!.stackTraceToString().contains("AuthzenResourceProperties"),
                    "the failure should name the missing SPI",
                )
            }
    }

    @Test
    fun `should start when every configured resource type has a projection`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.enabled=true",
                "valtimo.authorization.authzen.resource-types[$resourceType].name=projected",
            )
            .run { context ->
                assertTrue(context.startupFailure == null)
            }
    }

    /**
     * The whole replacement hinges on this annotation.
     *
     * `AuthorizationAutoConfiguration` declares `valtimoAuthorizationService`
     * `@ConditionalOnMissingBean(AuthorizationService::class)`, and that condition only sees beans
     * registered by *earlier* autoconfigurations. Lose the `before` and the condition matches
     * first, PBAC is constructed, and the context ends up with two `AuthorizationService` beans —
     * which surfaces as an ambiguity error at one of the 109 injection points, nowhere near the
     * cause. Nothing else in this suite would notice it going missing.
     */
    @Test
    fun `should be ordered before the PBAC autoconfiguration`() {
        val annotation = AuthzenAuthorizationAutoConfiguration::class.java
            .getAnnotation(org.springframework.boot.autoconfigure.AutoConfiguration::class.java)

        assertTrue(
            annotation.before.contains(AuthorizationAutoConfiguration::class),
            "AuthzenAuthorizationAutoConfiguration must run before AuthorizationAutoConfiguration, " +
                "or ValtimoAuthorizationService is constructed anyway. Declared before: " +
                annotation.before.joinToString(),
        )
    }

    /**
     * The suppressed bean is matched on `AuthorizationService`, so ours has to *be* one for the
     * condition to exclude it. A refactor that narrowed the bean's declared type would silently
     * stop replacing PBAC.
     */
    @Test
    fun `should expose the AuthZEN service as an AuthorizationService bean type`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.enabled=true",
                "valtimo.authorization.authzen.resource-types[$resourceType].name=projected",
            )
            .run { context ->
                assertEquals(1, context.getBeanNamesForType(AuthorizationService::class.java).size)
            }
    }

    data class ProjectedResource(val id: String)

    @Configuration
    class SupportingBeans {

        @Bean
        fun userManagementService(): UserManagementService = mock()

        @Bean
        fun objectMapper(): ObjectMapper = ObjectMapper().registerKotlinModule()

        @Bean
        fun projectedResourceProperties(): AuthzenResourceProperties<ProjectedResource> =
            object : AuthzenResourceProperties<ProjectedResource> {
                override val resourceType = ProjectedResource::class.java
                override fun idOf(entity: ProjectedResource) = entity.id
                override fun propertiesOf(entity: ProjectedResource) = emptyMap<String, Any?>()
            }
    }
}
