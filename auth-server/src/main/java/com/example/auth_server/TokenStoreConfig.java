package com.example.auth_server;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

@Configuration
public class TokenStoreConfig {

    @Bean
    // Cria e fornece uma fonte de chaves JWK (JSON Web Key) para a aplicação
    // Sempre que o bean for chamado, será criada uma nova fonte de chaves com um novo par de chaves RSA
    JWKSource<SecurityContext> jwkSource() {
        // Gera um novo par de chaves RSA
        KeyPair keyPair = generateRsaKey();
        // Obtém a chave pública RSA
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        // Obtém a chave privada RSA
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // Cria um objeto RSAKey a partir da chave pública e privada
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString()) // Define um ID único para a chave
                .build();
        // Cria um JWKSet contendo a chave RSA
        JWKSet jwkSet = new JWKSet(rsaKey);
        // Retorna uma fonte de chaves imutável contendo o JWKSet
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    // Cria e fornece um JwtDecoder que usa a fonte de chaves JWK para validar JWTs
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        // Configura o JwtDecoder para usar a fonte de chaves fornecida
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // Método auxiliar para gerar um par de chaves RSA
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            // Cria um gerador de pares de chaves RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // Inicializa o gerador com um tamanho de chave de 2048 bits
            keyPairGenerator.initialize(2048);
            // Gera o par de chaves
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            // Lança uma exceção se a geração da chave falhar
            throw new IllegalStateException(ex);
        }
        // Retorna o par de chaves gerado
        return keyPair;
    }
}
