package com.jldevs.jwt.model;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
public class Usuario implements UserDetails {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true)
	private String email;

	private String password;

	private boolean enabled = true;

	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(name = "usuario_roles",
			joinColumns = @JoinColumn(name = "usuario_id"))
	@Column(name = "role")
	private Set<String> roles = new HashSet<>();

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles.stream()
				.map(role -> new SimpleGrantedAuthority(
						role.startsWith("ROLE_") ? role : "ROLE_" + role))
				.collect(Collectors.toList());
	}

	public void addRole(String role) {
		if (roles == null) {
			roles = new HashSet<>();
		}
		roles.add(role.startsWith("ROLE_") ? role : "ROLE_" + role);
	}

	public Set<String> getRoles() {
		return roles;
	}

	public void setRoles(Set<String> roles) {
		this.roles = roles.stream()
				.map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
				.collect(Collectors.toSet());
	}

	// Getters y setters existentes...
	public Long getId() {
		return this.id;
	}

	@Override
	public String getUsername() {
		return email;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	@Override
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}
}