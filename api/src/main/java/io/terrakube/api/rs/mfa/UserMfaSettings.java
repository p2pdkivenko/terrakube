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
@Entity(name = "user_mfa_settings")
public class UserMfaSettings extends GenericAuditFields {
    @Id
    @JdbcTypeCode(Types.VARCHAR)
    @Convert(converter = IdConverter.class)
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_email", unique = true, nullable = false)
    private String userEmail;

    @Column(name = "mfa_enabled")
    private boolean mfaEnabled;

    @Column(name = "preferred_method")
    private String preferredMethod;
}
