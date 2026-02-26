package io.terrakube.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import io.terrakube.api.rs.mfa.MfaAttempt;

import java.time.LocalDateTime;
import java.util.UUID;

public interface MfaAttemptRepository extends JpaRepository<MfaAttempt, UUID> {

    long countByUserEmailAndCreatedDateAfter(String userEmail, LocalDateTime after);
}
