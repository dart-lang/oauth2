// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'package:collection/collection.dart';
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';

import 'credentials.dart';
import 'authorization_exception.dart';

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = const Duration(seconds: 10);

/// Handles a response from the authorization server that contains an access
/// token.
///
/// This response format is common across several different components of the
/// OAuth2 flow.
/// 
/// The scope strings will be separated by the provided [delimiter].
Credentials handleAccessTokenResponse(
    http.Response response,
    Uri tokenEndpoint,
    DateTime startTime,
    List<String> scopes,
    String delimiter) {
  if (response.statusCode != 200) _handleErrorResponse(response, tokenEndpoint);

  validate(condition, message) =>
      _validate(response, tokenEndpoint, condition, message);

  var contentTypeString = response.headers['content-type'];
  var contentType = contentTypeString == null
      ? null
      : new MediaType.parse(contentTypeString);

  // The spec requires a content-type of application/json, but some endpoints
  // (e.g. Dropbox) serve it as text/javascript instead.
  validate(contentType != null &&
      (contentType.mimeType == "application/json" ||
       contentType.mimeType == "text/javascript"  ||
       contentType.mimeType == "application/x-www-form-urlencoded" ||
       contentType.mimeType == "text/plain"),
      'content-type was "$contentType", expected "application/json", "application/x-www-form-urlencoded", or "text/plain"');

  Map<String, dynamic> parameters;

  if (contentType.mimeType == "text/plain" || contentType.mimeType == "application/x-www-form-urlencoded") {
    parameters = {};

    for (var unit in response.body.split('&')) {
      var separator = unit.lastIndexOf('=');

      // The '=' can't be the first or last character in a URL-encoded string
      //
      // For example, in 'a=b', the lowest index it can have is 1, and the greatest is
      // `unit.length - 2`.
      if (separator > 0 && separator < unit.length - 1) {
        var key = unit.substring(0, separator);
        var value = Uri.decodeComponent(unit.substring(separator + 1));
        parameters[key] = value;
      }
    }

  } else {
    try {
      var untypedParameters = JSON.decode(response.body);
      validate(untypedParameters is Map,
          'parameters must be a map, was "$parameters"');
      parameters = DelegatingMap.typed(untypedParameters);
    } on FormatException {
      validate(false, 'invalid JSON');
    }
  }

  for (var requiredParameter in ['access_token', 'token_type']) {
    validate(parameters.containsKey(requiredParameter),
        'did not contain required parameter "$requiredParameter"');
    validate(parameters[requiredParameter] is String,
        'required parameter "$requiredParameter" was not a string, was '
        '"${parameters[requiredParameter]}"');
  }

  // TODO(nweiz): support the "mac" token type
  // (http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01)
  validate(parameters['token_type'].toLowerCase() == 'bearer',
      '"$tokenEndpoint": unknown token type "${parameters['token_type']}"');

  var expiresIn = parameters['expires_in'];
  validate(expiresIn == null || expiresIn is int,
      'parameter "expires_in" was not an int, was "$expiresIn"');

  for (var name in ['refresh_token', 'scope']) {
    var value = parameters[name];
    validate(value == null || value is String,
        'parameter "$name" was not a string, was "$value"');
  }

  var scope = parameters['scope'] as String;
  if (scope != null) scopes = scope.split(delimiter);

  var expiration = expiresIn == null ? null :
      startTime.add(new Duration(seconds: expiresIn) - _expirationGrace);

  return new Credentials(
      parameters['access_token'],
      refreshToken: parameters['refresh_token'],
      tokenEndpoint: tokenEndpoint,
      scopes: scopes,
      expiration: expiration);
}

/// Throws the appropriate exception for an error response from the
/// authorization server.
void _handleErrorResponse(http.Response response, Uri tokenEndpoint) {
  validate(condition, message) =>
      _validate(response, tokenEndpoint, condition, message);

  // OAuth2 mandates a 400 or 401 response code for access token error
  // responses. If it's not a 400 reponse, the server is either broken or
  // off-spec.
  if (response.statusCode != 400 && response.statusCode != 401) {
    var reason = '';
    if (response.reasonPhrase != null && !response.reasonPhrase.isEmpty) {
      ' ${response.reasonPhrase}';
    }
    throw new FormatException('OAuth request for "$tokenEndpoint" failed '
        'with status ${response.statusCode}$reason.\n\n${response.body}');
  }

  var contentTypeString = response.headers['content-type'];
  var contentType = contentTypeString == null
      ? null
      : new MediaType.parse(contentTypeString);

  validate(contentType != null &&
      (contentType.mimeType == "application/json" || contentType.mimeType == "text/plain" ||
       contentType.mimeType == "application/x-www-form-urlencoded"),
      'content-type was "$contentType", expected "application/json", "application/x-www-form-urlencoded", or "text/plain"');

  var parameters;
  try {
    parameters = JSON.decode(response.body);
  } on FormatException {
    validate(false, 'invalid JSON');
  }

  validate(parameters.containsKey('error'),
      'did not contain required parameter "error"');
  validate(parameters["error"] is String,
      'required parameter "error" was not a string, was '
      '"${parameters["error"]}"');

  for (var name in ['error_description', 'error_uri']) {
    var value = parameters[name];
    validate(value == null || value is String,
        'parameter "$name" was not a string, was "$value"');
  }

  var description = parameters['error_description'];
  var uriString = parameters['error_uri'];
  var uri = uriString == null ? null : Uri.parse(uriString);
  throw new AuthorizationException(parameters['error'], description, uri);
}

void _validate(
    http.Response response,
    Uri tokenEndpoint,
    bool condition,
    String message) {
  if (condition) return;
  throw new FormatException('Invalid OAuth response for "$tokenEndpoint": '
      '$message.\n\n${response.body}');
}
