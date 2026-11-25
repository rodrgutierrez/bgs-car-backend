package com.duoc.api_gateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/api/v1/auth/**", "/doc/**", "/docs/**", "/v3/api-docs/**", "/actuator/**").permitAll()

                        // Catálogo público de tienda
                        .pathMatchers(HttpMethod.GET, "/api/v1/vehiculos/**", "/api/v2/vehiculos/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/v1/categorias/**", "/api/v2/categorias/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/v1/sucursales/**", "/api/v2/sucursales/**").permitAll()

                        // Flujo de compra y consultas de reservas (Vendedor solo puede hacer GET aquí)
                        .pathMatchers(HttpMethod.GET, "/api/v1/reservas/**", "/api/v2/reservas/**").hasAnyRole("ADMIN", "VENDEDOR", "CLIENTE")
                        .pathMatchers(HttpMethod.POST, "/api/v1/clientes/**", "/api/v1/reservas/**", "/api/v1/pagos/**").hasAnyRole("ADMIN", "CLIENTE")
                        .pathMatchers(HttpMethod.GET, "/api/v1/clientes/**", "/api/v1/estados-reserva/**").hasAnyRole("ADMIN", "VENDEDOR", "CLIENTE")

                        // Gestión de flota (POST/PUT/DELETE solo ADMIN)
                        .pathMatchers("/api/v1/vehiculos/**", "/api/v2/vehiculos/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/categorias/**", "/api/v2/categorias/**").hasRole("ADMIN")

                        // Módulos exclusivos de ADMIN
                        .pathMatchers("/api/v1/empleados/**", "/api/v2/empleados/**", "/api/v1/activos/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/reportes/**", "/api/v2/reportes/**").hasRole("ADMIN")
                        .anyExchange().hasRole("ADMIN")
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization", "X-Request-Id", "Location"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}