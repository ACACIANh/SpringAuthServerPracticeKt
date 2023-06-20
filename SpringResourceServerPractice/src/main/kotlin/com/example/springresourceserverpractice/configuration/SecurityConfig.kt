package com.example.springresourceserverpractice.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(
        http: HttpSecurity
    ): SecurityFilterChain {

        http
            .csrf { http -> http.disable() }
            .logout() { http -> http.disable() }
            .sessionManagement { http -> http.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { http ->
                http.anyRequest().authenticated()
            }
            .oauth2ResourceServer { http ->
                http.jwt {}
            }
        return http.build()
    }
}