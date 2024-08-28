
/**
 * Action taken on login / registration form submission.
 * Shows success or errors to UI.
 */
async function handleLoginSubmit() {

    const successDiv = $("#successDiv");
    const errorDiv = $("#errorDiv");
    errorDiv.hide();
    successDiv.hide();

    const userId = $("#userId").val();
    const applicationId = $("#applicationId").val();

    try {
        if (CEREMONY === REGISTRATION_CEREMONY) {
            const userDetails = {
                "username": $("#username").val(),
                "userDisplayName": $("#userDisplayName").val(),
                "userId": userId
            };
            await createCredential(userDetails, applicationId);
        } else if (CEREMONY === AUTHENTICATION_CEREMONY) {
            const templateName = $("#operationTemplate").val();
            await requestCredential(userId, applicationId, templateName, {});
            window.location.href = SERVLET_CONTEXT_PATH;
        } else {
            console.error("Unknown ceremony " + CEREMONY);
        }

        successDiv.show();

    } catch (e) {
        errorDiv.show()
        $("#errorMessage").html(e.message);
        console.log("Error occurred during a ceremony")
        console.log(e);
    }
}


/**
 * Run this block on web page load
 */
$(function() {

    const operationTemplateList = $('#operationTemplate option').toArray().map(o => o.value);
    if (operationTemplateList.length < 1) {
        console.log("There is no operation template to choose from.");
        $("#errorMessage").html("Create a login template first.");
        $("#errorDiv").show();
        $(":submit").attr("disabled", true);
    } else if (!operationTemplateList.includes("login")) {
        console.log("There is not operation template 'login'.");
        $('#settingsBlock').show();
    }

    // Check if any application is available to select
    const n_applications = $('#applicationId option').toArray().length;
    const applicationIdSelector = $('#applicationId');
    if (applicationIdSelector.is(":hidden") && applicationIdSelector.val() == null) {
        console.error("Application selector is hidden, but applicationId is null.")
        $("#errorMessage").html("No application is selected.");
        $("#errorDiv").show();
        $(":submit").attr("disabled", true);
    } else if (n_applications < 2) {
        console.log("There is no application to choose from.");
        $("#errorMessage").html("Create an application first.");
        $("#errorDiv").show();
        $(":submit").attr("disabled", true);
    }

    // Set action on Register button click
    $('#registerBtn').click(function(){
        $("#userId").prop('required', true);
        CEREMONY = REGISTRATION_CEREMONY;
    });

    // Set action on Login button click
    $('#loginBtn').click(function(){
        $("#userId").prop('required', false);
        CEREMONY = AUTHENTICATION_CEREMONY;
    });

    // Set action on WebAuthn Settings button click
    $('#settingsBtn').click(function () {
        const settingsBlock = $('#settingsBlock');
        if (settingsBlock.is(":visible")) {
            settingsBlock.hide();
        } else {
            settingsBlock.show();
        }
    });

    // Hint the userId == username == displayName if not overwritten
    const userIdField = $("#userId");
    userIdField.keyup(function () {
        $('#username').attr("placeholder", userIdField.val());
        $('#userDisplayName').attr("placeholder",  userIdField.val());
    });

});