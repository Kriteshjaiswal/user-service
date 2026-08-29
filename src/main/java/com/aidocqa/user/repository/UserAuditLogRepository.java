package com.aidocqa.user.repository;

import com.aidocqa.user.entity.UserAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserAuditLogRepository extends JpaRepository<UserAuditLog, Long> {
    List<UserAuditLog> findTop20ByUserIdOrderByTimestampDesc(Long userId);
    Page<UserAuditLog> findByUserIdOrderByTimestampDesc(Long userId, Pageable pageable);
}
