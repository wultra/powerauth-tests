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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
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

    @Serial
    private static final long serialVersionUID = -6389531428000326009L;

    @Id
    @Column(name = "activation_id", nullable = false)
    private String activationId;

    @Deprecated
    @Column(name = "server_public_key", nullable = false)
    private String serverPublicKey;

    @Column(name = "counter", nullable = false)
    private Long counter;

    @Column(name = "ctr_data", nullable = false)
    private String ctrData;

    @Deprecated
    @Column(name = "encrypted_device_private_key", nullable = false)
    private String encryptedDevicePrivateKey;

    @Deprecated
    @Column(name = "signature_biometry_key", nullable = false)
    private String signatureBiometryKey;

    @Deprecated
    @Column(name = "signature_knowledge_key_encrypted", nullable = false)
    private String signatureKnowledgeKeyEncrypted;

    @Deprecated
    @Column(name = "signature_knowledge_key_salt", nullable = false)
    private String signatureKnowledgeKeySalt;

    @Deprecated
    @Column(name = "signature_possession_key", nullable = false)
    private String signaturePossessionKey;

    @Deprecated
    @Column(name = "transport_master_key")
    private String transportMasterKey;

    @Column(name = "shared_secret_algorithm")
    private String sharedSecretAlgorithm;

    @Column(name = "temporary_key_act_sign_request_key")
    private String temporaryKeyActSignRequestKey;

    @Column(name = "pqc_server_public_key", columnDefinition = "TEXT")
    private String pqcServerPublicKey;

    @Column(name = "shared_info2_key")
    private String sharedInfo2Key;

    @Column(name = "mac_personalized_data_key")
    private String macPersonalizedDataKey;

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
