/*
 * PowerAuth test and related software components
 * Copyright (C) 2022 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.wultra.security.powerauth.app.testserver.database.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * Test application status entity.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
@Setter
@ToString
@NoArgsConstructor
@Entity
@Table(name = "pa_test_status")
public class TestStatusEntity implements Serializable {

    private static final long serialVersionUID = -6389531428000326009L;

    @Id
    @Column(name = "activation_id", nullable = false)
    private String activationId;

    @Column(name = "server_public_key", nullable = false)
    private String serverPublicKey;

    @Column(name = "counter", nullable = false)
    private Long counter;

    @Column(name = "ctr_data", nullable = false)
    private String ctrData;

    @Column(name = "encrypted_device_private_key", nullable = false)
    private String encryptedDevicePrivateKey;

    @Column(name = "signature_biometry_key", nullable = false)
    private String signatureBiometryKey;

    @Column(name = "signature_knowledge_key_encrypted", nullable = false)
    private String signatureKnowledgeKeyEncrypted;

    @Column(name = "signature_knowledge_key_salt", nullable = false)
    private String signatureKnowledgeKeySalt;

    @Column(name = "signature_possession_key", nullable = false)
    private String signaturePossessionKey;

    @Column(name = "transport_master_key", nullable = false)
    private String transportMasterKey;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TestStatusEntity that = (TestStatusEntity) o;
        return activationId.equals(that.activationId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(activationId);
    }
}
