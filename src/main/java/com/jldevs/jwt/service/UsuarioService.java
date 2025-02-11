package com.jldevs.jwt.service;

import com.jldevs.jwt.repository.UsuarioRepository;
import com.jldevs.jwt.model.Usuario;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService implements UserDetailsService {
	@Autowired
	private UsuarioRepository usuarioRepository;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return usuarioRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
	}

	public Usuario registrar(Usuario usuario) {
		// Validar si el email ya existe
		if (usuarioRepository.findByEmail(usuario.getUsername()).isPresent()) {
			throw new RuntimeException("El email ya está registrado");
		}
		return usuarioRepository.save(usuario);
	}

	public boolean existsByEmail(String email) {
		return usuarioRepository.findByEmail(email).isPresent();
	}

	public List<Usuario> getAll() {
		return usuarioRepository.findAll();
	}
}
