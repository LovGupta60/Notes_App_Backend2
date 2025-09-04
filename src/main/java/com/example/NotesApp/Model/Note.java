package com.example.NotesApp.Model;

import jakarta.persistence.*;
import lombok.*;
import java.time.OffsetDateTime;
@Entity
@Table(name = "notes")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Note {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    @Column(columnDefinition = "TEXT")
    private String content;
    private Long userId;
    private OffsetDateTime createdAt;



    private OffsetDateTime updatedAt;
    @Version
    private Long version;
}

