package com.duoc.api_gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import java.util.stream.Collectors;

import com.duoc.api_gateway.security.JwtService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiGatewayApplicationTests {

    @Autowired
    private RouteLocator routeLocator;

    @Autowired
    private JwtService jwtService;

    @Test
    void registraLasRutasDeServiciosYDocumentacion() {
        Set<String> routeIds = routeLocator.getRoutes()
                .map(Route::getId)
                .collectList()
                .block()
                .stream()
                .collect(Collectors.toSet());

        assertThat(routeIds).containsExactlyInAnyOrder(
                "ms-clientes",
                "ms-vehiculos",
                "ms-reservas",
                "ms-pagos",
                "ms-reportes",
                "ms-empleados",
                "ms-sucursales",
                "docs-clientes",
                "docs-vehiculos",
                "docs-reservas",
                "docs-pagos",
                "docs-reportes",
                "docs-empleados",
                "docs-sucursales"
        );
    }

    @Test
    void generaYValidaTokenJwtConRol() {
        String token = jwtService.generateToken("vendedor@duoc.cl", "Carlos", "Pérez", "VENDEDOR");

        assertThat(jwtService.isTokenValid(token)).isTrue();
        Claims claims = jwtService.extractAllClaims(token);
        assertThat(claims.getSubject()).isEqualTo("vendedor@duoc.cl");
        assertThat(claims.get("role", String.class)).isEqualTo("VENDEDOR");
    }
}