package com.aidocqa.user.kafka;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCreatedEvent {
    private Long userId;
    private String email;
    private String fullName;
    private String provider;
    private String role;
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
}
