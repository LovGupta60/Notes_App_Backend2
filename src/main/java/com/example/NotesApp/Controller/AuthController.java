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
        Optional<User> opt = userService.findByUsername(userDTO.getUsername());
        if (opt.isEmpty() || !passwordEncoder.matches(userDTO.getPassword(), opt.get().getPassword())) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        String token = jwtUtil.generateToken(opt.get().getUsername());

        // Just return token (React expects { token: "..." })
        return ResponseEntity.ok(Map.of("token", token));
    }
}
