/*
 * Callback handler for doing OAuth in-browser via JavaScript with no backend required, per se.
 *
 * This should be your callback in the HTML, see comments there. You'll receive a value with a field `credential`, and
 * this will be your encoded JWT token. The expectation is that you will send this token to your server via a JavaScript
 * HTTP request.
 */
function onLogin(resp) {
    var credentials = parseJwt(resp.credential);
    console.log(credentials);
}

function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
};