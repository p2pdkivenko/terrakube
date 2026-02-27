package io.terrakube.api.rs.mfa;

import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import io.terrakube.api.plugin.security.audit.GenericAuditFields;
import jakarta.persistence.*;
import io.terrakube.api.rs.IdConverter;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.UUID;

@NoArgsConstructor
@Getter
@Setter
@Entity(name = "mfa_credential")
public class MfaCredential extends GenericAuditFields {
    @Id
    @JdbcTypeCode(Types.VARCHAR)
    @Convert(converter = IdConverter.class)
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_email", nullable = false)
    private String userEmail;

    @Column(name = "type", nullable = false)
    private String type;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "credential_data", nullable = false, columnDefinition = "TEXT")
    private String credentialData;

    @Column(name = "last_used_date")
    private LocalDateTime lastUsedDate;
}
