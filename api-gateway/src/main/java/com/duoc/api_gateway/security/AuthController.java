package com.duoc.api_gateway.security;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        if (request.getCorreo() == null || request.getPassword() == null || request.getPassword().length() < 4) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("mensaje", "Credenciales inválidas"));
        }

        String email = request.getCorreo().trim().toLowerCase();
        String nombre = (request.getNombre() != null && !request.getNombre().isBlank())
                ? request.getNombre().trim()
                : email.split("@")[0];
        String apellido = (request.getApellido() != null && !request.getApellido().isBlank())
                ? request.getApellido().trim()
                : "BGS";

        String role;
        if (email.equals("admin@duoc.cl") || email.startsWith("admin@")) {
            role = "ADMIN";
        } else if (email.equals("vendedor@duoc.cl") || email.startsWith("vendedor@")) {
            role = "VENDEDOR";
        } else {
            role = "CLIENTE";
        }

        String token = jwtService.generateToken(email, nombre, apellido, role);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "nombre", nombre,
                "apellido", apellido,
                "correo", email,
                "role", role.toLowerCase()
        ));
    }

    @Data
    public static class LoginRequest {
        private String nombre;
        private String apellido;
        private String rut;
        private String correo;
        private String password;
    }
}