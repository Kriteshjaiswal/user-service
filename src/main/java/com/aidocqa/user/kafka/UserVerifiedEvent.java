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
public class UserVerifiedEvent {
    private Long userId;
    private String email;
    @Builder.Default
    private LocalDateTime verifiedAt = LocalDateTime.now();
}
