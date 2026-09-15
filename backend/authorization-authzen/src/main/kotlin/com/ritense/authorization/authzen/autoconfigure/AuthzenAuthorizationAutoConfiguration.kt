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
import com.ritense.authorization.AuthorizationEntityMapper
import com.ritense.authorization.AuthorizationService
import com.ritense.authorization.AuthorizationServiceHolder
import com.ritense.authorization.ResourceActionProvider
import com.ritense.authorization.authzen.AuthzenAuthorizationService
import com.ritense.authorization.authzen.AuthzenProperties
import com.ritense.authorization.authzen.client.AuthzenPdpClient
import com.ritense.authorization.authzen.mapping.AuthzenRequestMapper
import com.ritense.authorization.authzen.mapping.AuthzenResourceProperties
import com.ritense.authorization.authzen.mapping.AuthzenResourceTypeRegistry
import com.ritense.authorization.authzen.mapping.AuthzenSubjectFactory
import com.ritense.authorization.autoconfigure.AuthorizationAutoConfiguration
import com.ritense.authorization.specification.AuthorizationSpecificationFactory
import com.ritense.valtimo.contract.authentication.UserManagementService
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.codec.json.Jackson2JsonDecoder
import org.springframework.http.codec.json.Jackson2JsonEncoder
import org.springframework.web.reactive.function.client.WebClient

/**
 * Registers the AuthZEN-backed [AuthorizationService] **in place of** Valtimo's PBAC implementation.
 *
 * ## How the replacement happens
 *
 * `AuthorizationAutoConfiguration` declares its `valtimoAuthorizationService` bean
 * `@ConditionalOnMissingBean(AuthorizationService::class)`. Running `before` it means our
 * `AuthorizationService` is already registered when that condition is evaluated, so
 * `ValtimoAuthorizationService` is never constructed. The extension point was already there; this
 * just uses it.
 *
 * Everything *else* in `AuthorizationAutoConfiguration` still loads — the deployers, importers, the
 * PAP endpoints and `PbacRegistryService`. That is required rather than incidental:
 * `RelatedEntityAuthorizationRequest.init` calls `AuthorizationSupportedHelper.checkSupported`,
 * which resolves an `AuthorizationSpecificationFactory` bean by generic type and throws
 * `ResourceNotSupportedException` when there is none. The per-module factory beans must stay
 * registered even though they will never be invoked.
 *
 * With `valtimo.authorization.authzen.enabled` absent or false this class contributes nothing at
 * all, and Valtimo behaves exactly as it does today.
 */
@AutoConfiguration(before = [AuthorizationAutoConfiguration::class])
@EnableConfigurationProperties(AuthzenProperties::class)
@ConditionalOnProperty(
    prefix = "valtimo.authorization.authzen",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
class AuthzenAuthorizationAutoConfiguration {

    /**
     * Populating [AuthorizationServiceHolder] here is **mandatory**, not housekeeping.
     *
     * The holder is normally populated as a side effect inside the very bean method we suppress
     * (`AuthorizationAutoConfiguration.kt:104`), and `AuthorizationServiceHolder.currentInstance`
     * dereferences a nullable field with `!!`. Omitting this call leaves the holder null and turns
     * the first static, re-entrant lookup into a `NullPointerException` far from its cause.
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(AuthzenAuthorizationService::class)
    fun authzenAuthorizationService(
        authorizationSpecificationFactories: List<AuthorizationSpecificationFactory<*>>,
        mappers: List<AuthorizationEntityMapper<*, *>>,
        client: AuthzenPdpClient,
        requestMapper: AuthzenRequestMapper,
        actionProviders: List<ResourceActionProvider<*>>,
        userManagementService: UserManagementService
    ): AuthzenAuthorizationService {
        val service = AuthzenAuthorizationService(authorizationSpecificationFactories, mappers, client, requestMapper, actionProviders, userManagementService)
        AuthorizationServiceHolder(service)
        logger.warn {
            "AuthZEN authorization is ENABLED. The PDP now answers every point check, and query " +
                "filtering (getAuthorizationSpecification), getAuthorizedRoles, getPermissions and " +
                "getMapper/hasMapper are unimplemented — list pages, dashboards and task lists will " +
                "fail. This configuration is a spike and is not suitable for an environment with users."
        }
        return service
    }

    @Bean
    @ConditionalOnMissingBean(AuthzenPdpClient::class)
    fun authzenPdpClient(
        authzenWebClient: WebClient,
        objectMapper: ObjectMapper,
        properties: AuthzenProperties,
    ): AuthzenPdpClient = AuthzenPdpClient(authzenWebClient, objectMapper, properties)

    /**
     * A dedicated [WebClient] built on the application's [ObjectMapper], so the bytes the client
     * measures when chunking are the bytes it actually sends.
     */
    @Bean
    @ConditionalOnMissingBean(name = ["authzenWebClient"])
    fun authzenWebClient(objectMapper: ObjectMapper): WebClient =
        WebClient.builder()
            .codecs { configurer ->
                configurer.defaultCodecs().jackson2JsonEncoder(Jackson2JsonEncoder(objectMapper))
                configurer.defaultCodecs().jackson2JsonDecoder(Jackson2JsonDecoder(objectMapper))
            }
            .build()

    @Bean
    @ConditionalOnMissingBean(AuthzenResourceTypeRegistry::class)
    fun authzenResourceTypeRegistry(properties: AuthzenProperties): AuthzenResourceTypeRegistry =
        AuthzenResourceTypeRegistry(properties)

    @Bean
    @ConditionalOnMissingBean(AuthzenSubjectFactory::class)
    fun authzenSubjectFactory(
        userManagementService: UserManagementService,
        properties: AuthzenProperties,
    ): AuthzenSubjectFactory = AuthzenSubjectFactory(userManagementService, properties)

    @Bean
    @ConditionalOnMissingBean(AuthzenRequestMapper::class)
    fun authzenRequestMapper(
        subjectFactory: AuthzenSubjectFactory,
        resourceProperties: List<AuthzenResourceProperties<*>>,
        properties: AuthzenProperties,
    ): AuthzenRequestMapper {
        validateProjections(properties, resourceProperties)
        return AuthzenRequestMapper(subjectFactory, resourceProperties)
    }

    /**
     * Fails startup when a configured resource type has no [AuthzenResourceProperties] bean.
     *
     * Without a projection the PDP receives no attributes for that type, and a Cedar condition on an
     * absent attribute is simply *false* — so the type would deny every conditional policy while
     * looking perfectly healthy. A field-less marker type still needs a projector; writing the
     * trivial one is how you record that its policy surface really is empty.
     */
    private fun validateProjections(
        properties: AuthzenProperties,
        resourceProperties: List<AuthzenResourceProperties<*>>,
    ) {
        val projected = resourceProperties.map { it.resourceType.name }.toSet()
        val missing = properties.resourceTypes.keys.filterNot { it in projected }.sorted()
        if (missing.isNotEmpty()) {
            throw IllegalStateException(
                "No AuthzenResourceProperties bean registered for configured AuthZEN resource " +
                    "type(s): ${missing.joinToString(", ")}. Every managed type needs a projection " +
                    "declaring which attributes its policies may reference; register a trivial one " +
                    "returning an empty map if the type genuinely has no policy-relevant fields."
            )
        }
    }

    companion object {
        private val logger = KotlinLogging.logger {}
    }
}
