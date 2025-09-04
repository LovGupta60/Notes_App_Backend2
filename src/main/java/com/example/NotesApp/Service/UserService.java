package com.example.NotesApp.Service;

import com.example.NotesApp.Model.User;
import com.example.NotesApp.Repositary.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    @Autowired
    private UserRepository repo;
    @Autowired
    private  PasswordEncoder passwordEncoder;


    public User register(String username, String rawPassword) {
        if (repo.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already exists!");
        }
        User u = new User();
        u.setUsername(username);
        u.setPassword(passwordEncoder.encode(rawPassword));
        return repo.save(u);
    }

    public Optional<User> findByUsername(String username) {
        return repo.findByUsername(username);
    }
}
