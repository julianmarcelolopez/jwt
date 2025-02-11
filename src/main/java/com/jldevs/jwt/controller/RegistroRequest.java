package com.jldevs.jwt.controller;

import java.util.Set;
import lombok.Data;
import lombok.NonNull;

@Data
public class RegistroRequest {
	@NonNull
	private String email;

	@NonNull
	private String password;

	private Set<String> roles;
}