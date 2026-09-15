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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Configuration

/**
 * Pins the resource-type key spelling.
 *
 * A resource type key is a fully qualified class name, and Spring's relaxed binding splits an
 * unbracketed key on its dots into nested property names. It binds an **empty map** rather than
 * failing, so the PDP is simply never told about the type and nothing in the logs says why. This
 * test asserts both spellings so the trap stays visible rather than being re-encountered.
 */
class AuthzenPropertiesYamlBindingTest {

    private val runner = ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(PropertiesConfiguration::class.java))

    private val resourceType = "com.ritense.objectenapi.security.Object"

    @Test
    fun `should bind a bracketed resource type key`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.resource-types[$resourceType].name=object",
            )
            .run { context ->
                val properties = context.getBean(AuthzenProperties::class.java)
                assertEquals(setOf(resourceType), properties.resourceTypes.keys)
                assertEquals("object", properties.resourceTypes[resourceType]?.name)
            }
    }

    @Test
    fun `should bind nothing useful from an unbracketed resource type key`() {
        runner
            .withPropertyValues(
                "valtimo.authorization.authzen.resource-types.$resourceType.name=object",
            )
            .run { context ->
                val properties = context.getBean(AuthzenProperties::class.java)
                assertTrue(
                    properties.resourceTypes[resourceType] == null,
                    "An unbracketed FQCN key must not bind as a resource type. It bound: " +
                        "${properties.resourceTypes.keys}. Use bracket notation.",
                )
            }
    }

    @Test
    fun `should default to disabled`() {
        runner.run { context ->
            val properties = context.getBean(AuthzenProperties::class.java)
            assertEquals(false, properties.enabled)
            assertTrue(properties.resourceTypes.isEmpty())
        }
    }

    @Configuration
    @EnableConfigurationProperties(AuthzenProperties::class)
    class PropertiesConfiguration
}
