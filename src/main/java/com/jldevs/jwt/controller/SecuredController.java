package com.jldevs.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secured")
public class SecuredController {

	@GetMapping("/ejemplo")
	public ResponseEntity<String> securedEndpoint() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return ResponseEntity.ok("Acceso exitoso como: " + authentication.getName());
	}

	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")  // O también puedes usar @Secured("ROLE_ADMIN")
	public ResponseEntity<String> adminEndpoint() {
		return ResponseEntity.ok("Este es un endpoint solo para ADMIN");
	}

	@GetMapping("/user")
	@PreAuthorize("hasRole('USER')")  // O también puedes usar @Secured("ROLE_USER")
	public ResponseEntity<String> userEndpoint() {
		return ResponseEntity.ok("Este es un endpoint solo para USER");
	}
}