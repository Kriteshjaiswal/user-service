package com.aidocqa.user.repository;

import com.aidocqa.user.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, String> {
    List<UserSession> findByUserIdAndIsActiveTrueOrderByLastActivityAtDesc(Long userId);
    List<UserSession> findByUserIdOrderByCreatedAtDesc(Long userId);
    Optional<UserSession> findByIdAndIsActiveTrue(String id);

    @Modifying
    @Query("UPDATE UserSession s SET s.isActive = false WHERE s.userId = :userId AND s.id <> :currentSessionId")
    void deactivateOtherSessions(@Param("userId") Long userId, @Param("currentSessionId") String currentSessionId);

    @Modifying
    @Query("UPDATE UserSession s SET s.isActive = false WHERE s.userId = :userId")
    void deactivateAllUserSessions(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE UserSession s SET s.isActive = false WHERE s.isActive = true AND s.expiresAt < :now")
    int deactivateExpiredSessions(@Param("now") LocalDateTime now);
}
