/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.fido2.controller;

import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.fido2.service.Fido2SharedService;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.Map;

/**
 * Controller to display initial web page
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Controller
@AllArgsConstructor
@Slf4j
public class HomeController {

    private static final String REDIRECT_LOGIN = "redirect:/login";
    private static final String LOGIN_PAGE = "/login";
    private static final String PAYMENT_PAGE = "/payment";
    private static final String ERROR_PAGE = "/error";

    private final Fido2SharedService sharedService;
    private final ServletContext context;

    @ModelAttribute
    public void addAttributes(Map<String, Object> model) {
        model.put("servletContextPath", context.getContextPath());
    }

    @GetMapping("/")
    public String homePage(Map<String, Object> model) {
        return REDIRECT_LOGIN;
    }

    @GetMapping("/login")
    public String loginPage(Map<String, Object> model) {
        try {
            model.put("applications", sharedService.fetchApplicationNameList());
            model.put("templates", sharedService.fetchTemplateNameList());
            return LOGIN_PAGE;
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            model.put("exception", ex);
            model.put("errorMessage", ex.getMessage());
            return ERROR_PAGE;
        }
    }

    @GetMapping("/payment")
    public String profilePage(Map<String, Object> model) {
        try {
            model.put("templates", sharedService.fetchTemplateNameList());
            return PAYMENT_PAGE;
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            model.put("exception", ex);
            model.put("errorMessage", ex.getMessage());
            return ERROR_PAGE;
        }
    }

    @GetMapping("/logout")
    public String logoutPage(Map<String, Object> model) {
        return REDIRECT_LOGIN;
    }

}
