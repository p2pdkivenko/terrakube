package io.terrakube.api.rs.mfa;

import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import io.terrakube.api.plugin.security.audit.GenericAuditFields;
import jakarta.persistence.*;
import io.terrakube.api.rs.IdConverter;
import java.sql.Types;
import java.util.UUID;

@NoArgsConstructor
@Getter
@Setter
@Entity(name = "mfa_attempt")
public class MfaAttempt extends GenericAuditFields {
    @Id
    @JdbcTypeCode(Types.VARCHAR)
    @Convert(converter = IdConverter.class)
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_email", nullable = false)
    private String userEmail;

    @Column(name = "attempt_type", nullable = false)
    private String attemptType;

    @Column(name = "success", nullable = false)
    private boolean success;

    @Column(name = "ip_address")
    private String ipAddress;
}
