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

    @Column(name = "ec_server_public_key")
    private String ecServerPublicKey;

    @Column(name = "pqc_server_public_key", columnDefinition = "TEXT")
    private String pqcServerPublicKey;

    @Column(name = "counter", nullable = false)
    private Long counter;

    @Column(name = "ctr_data", nullable = false)
    private String ctrData;

    @Column(name = "encrypted_ec_device_private_key")
    private String encryptedEcDevicePrivateKey;

    @Column(name = "encrypted_pqc_device_private_key", columnDefinition = "TEXT")
    private String encryptedPqcDevicePrivateKey;

    @Column(name = "ec_device_public_key")
    private String ecDevicePublicKey;

    @Column(name = "pqc_device_public_key", columnDefinition = "TEXT")
    private String pqcDevicePublicKey;

    @Column(name = "biometry_factor_key")
    private String biometryFactorKey;

    @Column(name = "knowledge_factor_key_encrypted")
    private String knowledgeFactorKeyEncrypted;

    @Column(name = "knowledge_factor_key_salt")
    private String knowledgeFactorKeySalt;

    @Column(name = "possession_factor_key")
    private String possessionFactorKey;

    @Column(name = "shared_secret_algorithm")
    private String sharedSecretAlgorithm;

    @Column(name = "temporary_key_act_sign_request_key")
    private String temporaryKeyActSignRequestKey;

    @Column(name = "shared_info2_key")
    private String sharedInfo2Key;

    @Column(name = "mac_personalized_data_key")
    private String macPersonalizedDataKey;

    @Column(name = "status_blob_mac_key")
    private String statusBlobMacKey;

    @Deprecated
    @Column(name = "transport_master_key")
    private String transportMasterKey;

    @Column(name = "version")
    private Long version;

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
