package com.example.NotesApp.Controller;


import com.example.NotesApp.Model.Note;
import com.example.NotesApp.Model.User;
import com.example.NotesApp.Repositary.UserRepository;
import com.example.NotesApp.Security.JwtUtil;
import com.example.NotesApp.Service.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;
@RestController
@RequestMapping("/api/notes")
@CrossOrigin(origins = "http://localhost:3000/")
public class NoteController {
    @Autowired
    private  NoteService service;
    @Autowired
    private  UserRepository userRepo;
    @Autowired
    private  JwtUtil jwtUtil;
    public NoteController(NoteService service, UserRepository userRepo, JwtUtil jwtUtil) { this.service = service; this.userRepo = userRepo; this.jwtUtil = jwtUtil; }
    private Long currentUserId(Authentication auth) {
        String username = auth.getName();
        User u = userRepo.findByUsername(username).orElseThrow();
        return u.getId();
    }
    @GetMapping("/get")
    public List<Note> list(Authentication auth) { return service.listByUser(currentUserId(auth)); }
    @PostMapping("/create")
    public ResponseEntity<Note> create(Authentication auth, @RequestBody Note n) { Note saved = service.create(currentUserId(auth), n); return ResponseEntity.ok(saved); }
    @GetMapping("/{id}")
    public ResponseEntity<Note> get(Authentication auth, @PathVariable Long id) { return service.get(id).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build()); }
    @PutMapping("/{id}")
    public ResponseEntity<?> update(Authentication auth, @PathVariable Long id, @RequestBody Note n) { try { Note up = service.update(id, n, currentUserId(auth)); return ResponseEntity.ok(up); } catch(Exception e) { return ResponseEntity.status(409).body("conflict"); } }
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(Authentication auth, @PathVariable Long id) { service.delete(id, currentUserId(auth)); return ResponseEntity.noContent().build(); }
}
