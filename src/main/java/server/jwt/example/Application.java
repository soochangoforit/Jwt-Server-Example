package server.jwt.example;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import server.jwt.example.domain.AppUser;
import server.jwt.example.domain.Role;
import server.jwt.example.service.UserService;

import java.util.ArrayList;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}


	@Bean
	BCryptPasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}


/*
	// run after the application has initialized
	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role("ROLE_USER"));
			userService.saveRole(new Role("ROLE_MANAGER"));
			userService.saveRole(new Role("ROLE_ADMIN"));
			userService.saveRole(new Role("ROLE_SUPER_ADMIN"));

			userService.saveUser(new AppUser("aaaaa", "aaaaa", "12345", new ArrayList<>()));
			userService.saveUser(new AppUser("bbbbb", "bbbbb", "12345", new ArrayList<>()));
			userService.saveUser(new AppUser("ccccc", "ccccc", "12345", new ArrayList<>()));
			userService.saveUser(new AppUser("ddddd", "ddddd", "12345", new ArrayList<>()));

			userService.addRoleToUser("aaaaa", "ROLE_USER");
			userService.addRoleToUser("aaaaa", "ROLE_MANAGER");


			userService.addRoleToUser("bbbbb", "ROLE_MANAGER");
			userService.addRoleToUser("ccccc", "ROLE_ADMIN");

			userService.addRoleToUser("ddddd", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("ddddd", "ROLE_ADMIN");
			userService.addRoleToUser("ddddd", "ROLE_USER");
		};*/
	}

