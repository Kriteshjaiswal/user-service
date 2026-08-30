package com.aidocqa.user.repository;

import com.aidocqa.user.entity.UserVerification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserVerificationRepository extends JpaRepository<UserVerification, Long> {
    Optional<UserVerification> findTopByUserIdAndTypeAndIsUsedFalseOrderByCreatedAtDesc(Long userId, String type);
    Optional<UserVerification> findTopByUserIdAndIsUsedFalseOrderByCreatedAtDesc(Long userId);
    Optional<UserVerification> findByTokenAndIsUsedFalse(String token);
}
