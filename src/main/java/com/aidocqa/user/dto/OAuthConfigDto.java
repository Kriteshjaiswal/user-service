package com.aidocqa.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthConfigDto {
    private boolean googleConfigured;
    private boolean githubConfigured;
    private String googleClientId;
    private String githubClientId;
}
