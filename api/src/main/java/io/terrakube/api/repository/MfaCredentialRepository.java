package io.terrakube.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import io.terrakube.api.rs.mfa.MfaCredential;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MfaCredentialRepository extends JpaRepository<MfaCredential, UUID> {

    List<MfaCredential> findByUserEmail(String userEmail);

    List<MfaCredential> findByUserEmailAndType(String userEmail, String type);

    Optional<MfaCredential> findByIdAndUserEmail(UUID id, String userEmail);
}
