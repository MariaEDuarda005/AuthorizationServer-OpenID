package com.example.auth_server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityFilterConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception{
        // configurar as configurações do oauth2, obedecendo o protocolo
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // habilitando o openId, para ter o fluxo de autenticação padronizado
        http
            .getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(
            // utilizando com os valores padroes
            withDefaults());

        http
            .exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")))

        .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // todas as requisições feitas pelo authorization server precisam estar autenticadas
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()) // limitando o acesso apenas a requisições autenticadas
        .formLogin(withDefaults()); // se não for autenticada a pagina de login retorna as configurações padroes

        return http.build();
    }
}
