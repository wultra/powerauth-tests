
const operationParamKeys = []
const operationParamValues = []

/**
 * Action taken on payment action.
 * Shows success or errors to UI.
 */
async function handlePaymentSubmit() {

    const successDiv = $("#successDiv");
    const errorDiv = $("#errorDiv");
    errorDiv.hide();
    successDiv.hide();

    const username = $("#username").val();
    const applicationId = $("#applicationId").val();
    const templateName = $("#operationTemplate").val();
    let operationParameters = {
        "amount": $("#amount").val(),
        "currency": $("#currency").val(),
        "iban": $("#iban").val(),
    }

    for (let i = 0; i < operationParamKeys.length; ++i) {
        operationParameters[operationParamKeys[i].value] = operationParamValues[i].value
    }

    try {
        await requestCredential(username, applicationId, templateName, operationParameters);
        successDiv.show();

    } catch (e) {
        errorDiv.show()
        $("#errorMessage").html(e.message);
        console.log("Error occurred during a ceremony")
        console.log(e);
    }
}

/**
 * Create additional Operation parameter fields.
 */
function createOperationParameter() {
    const formFields = $("#divFormFields");
    const count = operationParamKeys.length;

    const key = document.createElement("input");
    key.type = "text";
    key.id = "key" + count;
    key.placeholder = "Key";
    key.class = "form-control";
    key.style.width = "50%";

    const value = document.createElement("input");
    value.type = "text";
    value.id = "value" + count;
    value.placeholder = "Value";
    value.class = "form-control";
    value.style.width = "50%";

    const div = document.createElement("div");
    div.class = "form-group input-group";
    div.style.width = "100%";

    operationParamKeys[count] = key;
    operationParamValues[count] = value;

    div.append(key);
    div.append(value);
    formFields.append(div);
}

$(function() {

    const operationTemplateList = $('#operationTemplate option').toArray().map(o => o.value);
    if (operationTemplateList.length < 1) {
        console.log("There is no operation template to choose from.");
        $("#errorMessage").html("Create a payment template first.");
        $("#errorDiv").show();
        $(":submit").attr("disabled", true);
    } else if (!operationTemplateList.includes("payment")) {
        console.log("There is not operation template 'payment'.");
    }

    // Set action on Register button click
    $('#payBtn').click(function(){
        CEREMONY = AUTHENTICATION_CEREMONY;
    });

    // Set action on Logout button click
    $('#logoutBtn').click(function(){
        window.location.href = SERVLET_CONTEXT_PATH + "/logout";
    });

    // Set action on Add operation parameter button click
    $('#addFieldBtn').click(function(){
        createOperationParameter();
    });

});
