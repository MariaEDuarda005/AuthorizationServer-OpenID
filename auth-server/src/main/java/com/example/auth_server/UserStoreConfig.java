package com.example.auth_server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserStoreConfig {

    @Bean
    // consultar usuarios no processo de autenticação, usando o bean automaticamente ele vai ser autenticado no formulario de login
    UserDetailsService userDetailsService() {
        var userDetailsManager = new InMemoryUserDetailsManager();

        // consulta usuario com esse componente
        userDetailsManager.createUser(
                User.withUsername("user")
                .password("{noop}password")
                .roles("USER")
                .build() // noop - significa nenhuma codificação
        );

        return userDetailsManager;
    }
}
