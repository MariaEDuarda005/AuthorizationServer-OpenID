package com.example.auth_server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@Configuration
public class ClientStoreConfig {

    @Bean
    RegisteredClientRepository repository(){
        // estrategia em memoria para facilitar
        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()) // estrategia de geração aleatoria
                .clientId("client-server") // para informar quem é o cliente
                .clientSecret("{noop}secret") // tbm tem uma secret
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // vai ser um metodo de autenticação
                // definir os Grant Type, os fluxos de autorização que vai seguir
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // mais comum, utilizados em aplicações que tem o front end
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-server-oidc") // informa a uri da aplicação cliente que deve receber o encode gerado, da aplicação cliente
                // escopos associados a ela, permissoes que o usuario vai dar para a aplicação cliente
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                // exiba uma tela de consentimento informando que a aplicação cliente vai ter esses escopos de acesso
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }
}
