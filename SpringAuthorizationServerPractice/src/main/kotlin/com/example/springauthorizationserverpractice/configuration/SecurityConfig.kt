package com.example.springauthorizationserverpractice.configuration

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.UUID

@Configuration
class SecurityConfig {

    @Bean
    fun filterChain(
        http: HttpSecurity,
    ): SecurityFilterChain {

        http.csrf { http -> http.disable() }

        OAuth2AuthorizationServerConfigurer()
            .apply { http.apply(this) } // OAuth2AuthorizationServerConfigurer 등록
            .registeredClientRepository(registeredClientRepository()) // Client Credentials 데이터 저장소 등록
            .authorizationService(authorizationService()) // OAuth Authorization (Access Token) 내역 데이터 저장소 등록
            .tokenGenerator(JwtGenerator(jwtEncoder(jwkSource()))) // Access Token은 JWT 선택 (기본 구현은 Opaque Token)
            .authorizationServerSettings(authorizationServerSettings()) // Authorization Server 환경 셋팅 (예: Token Endpoint 커스터마이징)
        // ...
        return http.build()
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            // ...
            .clientId("client")
//            .clientSecret("client")       //authorization 헤더에 다음 값 추가 Basic Y2xpZW50OmNsaWVudA==
            .clientSecret(passwordEncoder().encode("client"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Authorization: Basic {base64 인코딩 문자열}
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // client_credentials 이용
            .tokenSettings(
                TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build()
            ) // Token 유효 2시간으로 설정
            .scope("custom")
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun authorizationService(): OAuth2AuthorizationService =
        InMemoryOAuth2AuthorizationService()

    /**
     * jwt 생성에 필요한 RSA키 generate, 실제 운영에 사용하려면 KeyStore에 저장해야한다.
     */
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    private fun generateRsaKey(): KeyPair =
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder =
        NimbusJwtEncoder(jwkSource)

    /**
     * 여러 endpoint URI를 커스터마이징할 수 있다.
     */
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().tokenEndpoint("/v1/oauth2/token").build()

    //===

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }
}