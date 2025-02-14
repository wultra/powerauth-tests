
const REGISTRATION_CEREMONY = "registration";
const AUTHENTICATION_CEREMONY = "authentication";
let CEREMONY;

/**
 * WebAuthn ceremony to create a new credential on register request.
 */
async function createCredential(userDetails, applicationId) {
    const options = await fetchRegistrationOptions(userDetails, applicationId);
    const credential = await navigator.credentials.create({
        publicKey: options
    });
    console.log("Public Key Credential Created")

    const registerResponse = await registerCredentials(userDetails.userId, applicationId, credential)
    console.log("PowerAuth Registration Response")
    console.log(JSON.stringify(registerResponse, null, 2));
    if (registerResponse.activationStatus !== "ACTIVE") {
        throw Error("Registration process failed, activation is not in state 'ACTIVE'.");
    }
}

/**
 * WebAuthn ceremony to request an existing credential on login request.
 */
async function requestCredential(userId, applicationId, templateName, operationParameters) {
    const options = await fetchAssertionOptions(userId, applicationId, templateName, operationParameters);
    const credential = await navigator.credentials.get({
        publicKey: options
    });

    console.log("Public Key Credential Retrieved")

    const authenticateResponse = await verifyAssertion(applicationId, options.challenge, credential)
    console.log("PowerAuth Authentication Response")
    console.log(JSON.stringify(authenticateResponse, null, 2));
    if (!authenticateResponse.assertionValid) {
        throw Error("Assertion is not valid.");
    }
}

/**
 * Fetch and return public key credential creation options.
 * @param userDetails User ID, Username and User Display Name from user input.
 * @param applicationId Application ID from user input.
 * @returns public key credential creation options
 */
async function fetchRegistrationOptions(userDetails, applicationId) {

    const fetchOptionsRequest = {
        "userId": userDetails.userId,
        "username": userDetails.username,
        "userDisplayName": userDetails.userDisplayName,
        "applicationId": applicationId
    };

    let options = await post("/registration/options", fetchOptionsRequest)

    // Build selection criteria from WebAuthn settings customisable from UI
    const userVerification = $("#userVerification").val();
    const residentKey =  $("#residentKey").val();
    const authenticatorAttachment =  $("#authenticatorAttachment").val();
    let authenticatorSelection = {
        userVerification: userVerification,
        residentKey: residentKey,
        requireResidentKey: residentKey === "required",
    }

    // If user did not choose platform or cross-platform attachment, omit the field to allow both.
    if (authenticatorAttachment === "platform" || authenticatorAttachment === "cross-platform") {
        authenticatorSelection = {
            ...authenticatorSelection,
            authenticatorAttachment: authenticatorAttachment
        }
    }

    // Add WebAuthn settings customisable from UI
    options = {
        ...options,
        authenticatorSelection: authenticatorSelection,
        attestation: $("#attestation").val()
    }

    console.log("Public Key Credential Creation Options")
    console.log(JSON.stringify(options, null, 2));

    // Some fields have to be passed as buffer to navigator.create()
    const byteEncoder = new TextEncoder();
    return {
        ...options,
        challenge: byteEncoder.encode(options.challenge),
        user: {
            ...options.user,
            id: byteEncoder.encode(options.user.id)
        },
        excludeCredentials: options.excludeCredentials?.map( credentialDescriptor => ({
            ...credentialDescriptor,
            id: toBuffer(credentialDescriptor.id)
        }) )
    }

}

/**
 * Fetch and return public key credential request options.
 * @param userId User ID from user input, may be empty.
 * @param applicationId Application ID from user input.
 * @param templateName Template name to use.
 * @param operationParameters Parameters of the operation.
 * @returns public key credential request options
 */
async function fetchAssertionOptions(userId, applicationId, templateName, operationParameters) {

    const fetchOptionsRequest = {
        "userId": userId,
        "applicationId": applicationId,
        "templateName": templateName,
        "operationParameters": operationParameters
    };

    let options = await post("/assertion/options", fetchOptionsRequest)
    // Add WebAuthn settings customisable from UI
    options = {
        ...options,
        userVerification:$("#userVerification").val(),
    }

    console.log("Public Key Credential Request Options")
    console.log(JSON.stringify(options, null, 2));

    // Some fields have to be passed as buffer to navigator.get()
    const byteEncoder = new TextEncoder();
    return {
        ...options,
        challenge: byteEncoder.encode(options.challenge),
        allowCredentials: options.allowCredentials?.map( credentialDescriptor => ({
            ...credentialDescriptor,
            id: toBuffer(credentialDescriptor.id)
        }) ),
        extensions: {
            ...options.extensions,
        }
    }
}

/**
 * Send register credential request to PowerAuth Server
 * @param userId User ID from user input.
 * @param applicationId Application ID from user input.
 * @param credential Newly created credential.
 * @returns JSON response from PowerAuth Server.
 */
async function registerCredentials(userId, applicationId, credential) {
    const userVerification = $("#userVerification").val();

    // Although getTransports() is required by WebAuthn specification, some browsers do not support it
    let transports = [];
    if (typeof credential.response.getTransports === 'function') {
        transports = credential.response.getTransports();
    }

    // RP entity and allowedOrigins are added on backend level
    const requestBody = {
        applicationId: applicationId,
        userId: userId,
        userVerificationRequired: userVerification === "required",
        id: credential.id,
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        response: {
            clientDataJSON: toBase64(credential.response.clientDataJSON),
            attestationObject: toBase64(credential.response.attestationObject),
            transports: transports
        }
    };

    console.log("PowerAuth Registration Request")
    return await post("/registration", requestBody);
}

/**
 * Send verify assertion request to PowerAuth server.
 * @param applicationId Application ID from user input.
 * @param challenge Challenge received from PowerAuth server.
 * @param credential Retrieved credential.
 * @returns JSON response from PowerAuth Server.
 */
async function verifyAssertion(applicationId, challenge, credential) {
    const decoder = new TextDecoder();
    const requestBody = {
        applicationId: applicationId,
        id: credential.id,
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        response: {
            clientDataJSON: toBase64(credential.response.clientDataJSON),
            authenticatorData: toBase64(credential.response.authenticatorData),
            signature: toBase64(credential.response.signature),
            userHandle: credential.response.userHandle == null ? null : decoder.decode(credential.response.userHandle)
        },
        expectedChallenge: decoder.decode(challenge),
        userVerificationRequired: $("#userVerification").val() === "required"
    };

    console.log("PowerAuth Assertion Request")
    return await post("/assertion", requestBody);
}

/**
 * Send a POST request to backend service.
 * @param apiPath API path for the request.
 * @param requestBody Body of the request.
 * @returns JSON response.
 */
async function post(apiPath, requestBody) {
    console.log("POST " + apiPath);
    console.log(JSON.stringify(requestBody, null, 2));
    const response = await fetch(SERVLET_CONTEXT_PATH + apiPath, {
        method: "POST",
        body: JSON.stringify(requestBody),
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });

    const json = await response.json();

    if (response.status !== 200) {
        if (json.hasOwnProperty("responseObject")) {
            throw Error(json.responseObject.message);
        } else if (json.hasOwnProperty("error")) {
            throw Error(json.error);
        }
        throw Error(JSON.stringify(json));
    }

    return json;
}

/**
 * Convert buffer to base64 string.
 * @param buffer Buffer to convert.
 * @returns {string} Converted string.
 */
function toBase64(buffer) {
    const byteView = new Uint8Array(buffer);
    let str = "";
    for (const charCode of byteView) {
        str += String.fromCharCode(charCode);
    }
    return btoa(str);
}

/**
 * Convert base64 string to buffer.
 * @param base64 String to convert.
 * @returns {ArrayBufferLike} Converted array.
 */
function toBuffer(base64) {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}


