package com.wultra.security.powerauth.webflow.test;

import com.wultra.security.powerauth.webflow.configuration.WebFlowTestConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = WebFlowTestConfiguration.class)
@EnableConfigurationProperties
public class LoginTest {

    private WebFlowTestConfiguration config;

    @Autowired
    public void setWebFlowTestConfiguration(WebFlowTestConfiguration config) {
        this.config = config;
    }

    By loginLink = By.xpath("//a[@href='#LOGIN']");
    By loginButton = By.xpath("//button[@type='submit' and text()='Log in']");
    By usernameField = By.xpath("//div[@class='panel-body']//input[@type='text' and @placeholder='Login number']");
    By passwordField = By.xpath("//div[@class='panel-body']//input[@type='password' and @placeholder='Password']");
    By signInButton = By.xpath("//button[@type='submit']/span[text()='Sign In']/..");
    By consentOption = By.id("CONSENT_LOGIN");
    By confirmButton = By.xpath("//button[@type='submit']/span[text()='Confirm']/..");
    By messageSuccess = By.xpath("//div[@class='message-success title']");
    By logoutButton = By.xpath("//button[@type='submit' and text()='Log out']");

    @Test
    public void loginTest() {
        WebDriver driver = config.getWebDriver();
        driver.get(config.getWebFlowClientUrl());
        WebDriverWait wait = config.getWebDriverWait();
        wait.until(ExpectedConditions.presenceOfElementLocated(loginLink));
        WebElement el = driver.findElement(loginLink);
        el.click();
        wait.until(ExpectedConditions.presenceOfElementLocated(loginButton));
        submit(loginButton);
        wait.until(ExpectedConditions.presenceOfElementLocated(usernameField));
        wait.until(ExpectedConditions.presenceOfElementLocated(passwordField));
        wait.until(ExpectedConditions.presenceOfElementLocated(signInButton));
        el = driver.findElement(usernameField);
        el.sendKeys("test");
        el = driver.findElement(passwordField);
        el.sendKeys("test");
        submit(signInButton);
        wait.until(ExpectedConditions.presenceOfElementLocated(consentOption));
        wait.until(ExpectedConditions.presenceOfElementLocated(confirmButton));
        click(consentOption);
        submit(confirmButton);
        wait.until(ExpectedConditions.presenceOfElementLocated(messageSuccess));
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        submit(logoutButton);
        wait.until(ExpectedConditions.presenceOfElementLocated(loginLink));
    }

    private void click(By by) {
        WebElement el = config.getWebDriver().findElement(by);
        JavascriptExecutor executor = (JavascriptExecutor) config.getWebDriver();
        executor.executeScript("arguments[0].click();", el);
    }

    private void submit(By by) {
        WebElement el = config.getWebDriver().findElement(by);
        el.submit();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
        }
    }
}
