package com.aidocqa.user.repository;

import com.aidocqa.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByProviderAndProviderId(String provider, String providerId);
    boolean existsByEmail(String email);

    @Query("SELECT u FROM User u WHERE " +
           "(:query IS NULL OR :query = '' OR LOWER(u.fullName) LIKE LOWER(CONCAT('%', :query, '%')) OR LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%'))) AND " +
           "(:role IS NULL OR :role = '' OR u.role = :role) AND " +
           "(:provider IS NULL OR :provider = '' OR u.provider = :provider) AND " +
           "(:status IS NULL OR :status = '' OR u.accountStatus = :status)")
    Page<User> searchUsers(
            @Param("query") String query,
            @Param("role") String role,
            @Param("provider") String provider,
            @Param("status") String status,
            Pageable pageable
    );
}
