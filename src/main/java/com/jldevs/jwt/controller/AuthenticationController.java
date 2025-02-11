package com.jldevs.jwt.controller;

import com.jldevs.jwt.service.JwtService;
import com.jldevs.jwt.model.LoginRequest;
import com.jldevs.jwt.model.Usuario;
import com.jldevs.jwt.service.UsuarioService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UsuarioService usuarioService;

	@Autowired
	private JwtService jwtService;

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getEmail(),
						loginRequest.getPassword()
				)
		);

		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		String token = jwtService.generateToken(userDetails);

		return ResponseEntity.ok(token);
	}

	@Autowired
	private PasswordEncoder passwordEncoder;

//	@PostMapping("/registro")
//	public ResponseEntity<String> registrarUsuario(@RequestBody Usuario usuario) {
//		// Encriptar contraseña antes de guardar
//		usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
//
//		Usuario usuarioGuardado = usuarioService.registrar(usuario);
//		return ResponseEntity.ok("Usuario registrado con ID: " + usuarioGuardado.getId());
//	}

	@PostMapping("/registro")
	public ResponseEntity<?> registrarUsuario(@RequestBody RegistroRequest registroRequest) {
		// Verificar si el usuario ya existe
		if (usuarioService.existsByEmail(registroRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body("Error: El email ya está en uso");
		}

		// Crear nuevo usuario
		Usuario usuario = new Usuario();
		usuario.setEmail(registroRequest.getEmail());
		usuario.setPassword(passwordEncoder.encode(registroRequest.getPassword()));

		// Asignar roles
		if (registroRequest.getRoles() == null || registroRequest.getRoles().isEmpty()) {
			// Si no se especifican roles, asignar ROLE_USER por defecto
			usuario.addRole("ROLE_USER");
		} else {
			registroRequest.getRoles().forEach(usuario::addRole);
		}

		usuarioService.registrar(usuario);

		return ResponseEntity.ok("Usuario registrado exitosamente!");
	}

	@GetMapping("/usuarios")
	public ResponseEntity<List<Usuario>> registrarUsuario() {
		return ResponseEntity.ok(usuarioService.getAll());
	}
}