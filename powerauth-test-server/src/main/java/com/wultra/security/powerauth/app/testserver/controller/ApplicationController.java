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

package com.wultra.security.powerauth.app.testserver.controller;

import com.wultra.security.powerauth.app.testserver.model.request.ConfigureApplicationRequest;
import com.wultra.security.powerauth.app.testserver.service.ApplicationService;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for application actions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController
@RequestMapping("application")
public class ApplicationController {

    private final ApplicationService applicationService;

    /**
     * Controller constructor.
     * @param applicationService Application service.
     */
    @Autowired
    public ApplicationController(ApplicationService applicationService) {
        this.applicationService = applicationService;
    }

    /**
     * Configure an application.
     * @param request Configure an application request.
     * @return Configure an application response.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    public Response createActivation(@RequestBody ObjectRequest<ConfigureApplicationRequest> request) {
        return applicationService.configureApplication(request.getRequestObject());
    }

}
