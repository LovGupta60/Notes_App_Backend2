package com.example.NotesApp.Controller;

import com.example.NotesApp.Model.User;
import com.example.NotesApp.Model.UserDTO;
import com.example.NotesApp.Security.JwtUtil;
import com.example.NotesApp.Service.UserService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;
@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "http://localhost:3000/")
public class AuthController {

    @Autowired
    private  UserService userService;
    @Autowired
    private  PasswordEncoder passwordEncoder;
    @Autowired
    private  JwtUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserDTO userDTO) {
        if (userDTO.getPassword() == null || userDTO.getUsername() == null) {
            return ResponseEntity.badRequest().body("Username and password are required");
        }

        try {
            User createdUser = userService.register(userDTO.getUsername(), userDTO.getPassword());
            return ResponseEntity.ok(createdUser);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDTO userDTO) {
        try {
            // Authenticate using Spring Security
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            userDTO.getUsername(),
                            userDTO.getPassword()
                    )
            );

            // If authentication is successful, generate JWT
            String token = jwtUtil.generateToken(userDTO.getUsername());

            return ResponseEntity.ok(Map.of("token", token));

        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

}
