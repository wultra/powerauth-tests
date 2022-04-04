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
 * Test application configuration entity.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
@Setter
@ToString
@NoArgsConstructor
@Entity
@Table(name = "pa_test_config")
public class TestConfigEntity implements Serializable {

    private static final long serialVersionUID = -7771850381097895836L;

    @Id
    @Column(name = "application_id", nullable = false)
    private Long applicationId;

    @Column(name = "application_name", nullable = false)
    private String applicationName;

    @Column(name = "application_key", nullable = false)
    private String applicationKey;

    @Column(name = "application_secret", nullable = false)
    private String applicationSecret;

    @Column(name = "master_public_key", nullable = false)
    private String masterPublicKey;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TestConfigEntity that = (TestConfigEntity) o;
        return applicationKey.equals(that.applicationKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(applicationKey);
    }
}
