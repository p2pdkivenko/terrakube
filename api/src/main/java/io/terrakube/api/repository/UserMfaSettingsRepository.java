package io.terrakube.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import io.terrakube.api.rs.mfa.UserMfaSettings;

import java.util.Optional;
import java.util.UUID;

public interface UserMfaSettingsRepository extends JpaRepository<UserMfaSettings, UUID> {

    Optional<UserMfaSettings> findByUserEmail(String userEmail);
}
