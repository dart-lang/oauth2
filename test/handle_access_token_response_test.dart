// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:oauth2/src/handle_access_token_response.dart';
import 'package:oauth2/src/parameters.dart';
import 'package:test/test.dart';

import 'utils.dart';

final Uri tokenEndpoint = Uri.parse('https://example.com/token');

final DateTime startTime = DateTime.now();

oauth2.Credentials handle(http.Response response,
        {GetParameters? getParameters}) =>
    handleAccessTokenResponse(
        response, tokenEndpoint, startTime, ['scope'], ' ',
        getParameters: getParameters);

void main() {
  group('an error response', () {
    oauth2.Credentials handleError(
            {String body = '{"error": "invalid_request"}',
            int statusCode = 400,
            Map<String, String> headers = const {
              'content-type': 'application/json'
            }}) =>
        handle(http.Response(body, statusCode, headers: headers));

    test('causes an AuthorizationException', () {
      expect(handleError, throwsAuthorizationException);
    });

    test('with a 401 code causes an AuthorizationException', () {
      expect(() => handleError(statusCode: 401), throwsAuthorizationException);
    });

    test('with an unexpected code causes a FormatException', () {
      expect(() => handleError(statusCode: 500), throwsFormatException);
    });

    test('with no content-type causes a FormatException', () {
      expect(() => handleError(headers: {}), throwsFormatException);
    });

    test('with a non-JSON content-type causes a FormatException', () {
      expect(() => handleError(headers: {'content-type': 'text/plain'}),
          throwsFormatException);
    });

    test('with a non-JSON, non-plain content-type causes a FormatException',
        () {
      expect(() => handleError(headers: {'content-type': 'image/png'}),
          throwsFormatException);
    });

    test(
        'with a JSON content-type and charset causes an '
        'AuthorizationException', () {
      expect(
          () => handleError(
              headers: {'content-type': 'application/json; charset=UTF-8'}),
          throwsAuthorizationException);
    });

    test('with invalid JSON causes a FormatException', () {
      expect(() => handleError(body: 'not json'), throwsFormatException);
    });

    test('with a non-string error causes a FormatException', () {
      expect(() => handleError(body: '{"error": 12}'), throwsFormatException);
    });

    test('with a non-string error_description causes a FormatException', () {
      expect(
          () => handleError(
              body: jsonEncode(
                  {'error': 'invalid_request', 'error_description': 12})),
          throwsFormatException);
    });

    test('with a non-string error_uri causes a FormatException', () {
      expect(
          () => handleError(
              body: jsonEncode({'error': 'invalid_request', 'error_uri': 12})),
          throwsFormatException);
    });

    test('with a string error_description causes a AuthorizationException', () {
      expect(
          () => handleError(
                  body: jsonEncode({
                'error': 'invalid_request',
                'error_description': 'description'
              })),
          throwsAuthorizationException);
    });

    test('with a string error_uri causes a AuthorizationException', () {
      expect(
          () => handleError(
                  body: jsonEncode({
                'error': 'invalid_request',
                'error_uri': 'http://example.com/error'
              })),
          throwsAuthorizationException);
    });
  });

  group('a success response', () {
    oauth2.Credentials handleSuccess(
        {String contentType = 'application/json',
        Object? accessToken = 'access token',
        Object? tokenType = 'bearer',
        Object? expiresIn,
        Object? refreshExpiresIn,
        Object? refreshToken,
        Object? scope}) {
      return handle(http.Response(
          jsonEncode({
            'access_token': accessToken,
            'token_type': tokenType,
            'expires_in': expiresIn,
            'refresh_expires_in': refreshExpiresIn,
            'refresh_token': refreshToken,
            'scope': scope
          }),
          200,
          headers: {'content-type': contentType}));
    }

    test('returns the correct credentials', () {
      var credentials = handleSuccess();
      expect(credentials.accessToken, equals('access token'));
      expect(credentials.tokenEndpoint.toString(),
          equals(tokenEndpoint.toString()));
    });

    test('with no content-type causes a FormatException', () {
      expect(() => handleSuccess(contentType: ''), throwsFormatException);
    });

    test('with a non-JSON content-type causes a FormatException', () {
      expect(() => handleSuccess(contentType: 'text/plain'),
          throwsFormatException);
    });

    test(
        'with a JSON content-type and charset returns the correct '
        'credentials', () {
      var credentials =
          handleSuccess(contentType: 'application/json; charset=UTF-8');
      expect(credentials.accessToken, equals('access token'));
    });

    test('with a JavScript content-type returns the correct credentials', () {
      var credentials = handleSuccess(contentType: 'text/javascript');
      expect(credentials.accessToken, equals('access token'));
    });

    test('with custom getParameters() returns the correct credentials', () {
      var body = '_${jsonEncode({
            'token_type': 'bearer',
            'access_token': 'access token'
          })}';
      var credentials = handle(
        http.Response(body, 200, headers: {'content-type': 'text/plain'}),
        getParameters: (contentType, body) =>
            jsonDecode(body.substring(1)) as Map<String, dynamic>,
      );
      expect(credentials.accessToken, equals('access token'));
      expect(credentials.tokenEndpoint.toString(),
          equals(tokenEndpoint.toString()));
    });

    test('throws a FormatException if custom getParameters rejects response',
        () {
      var response = http.Response(
          jsonEncode({
            'access_token': 'access token',
            'token_type': 'bearer',
            'expires_in': 24,
            'refresh_token': 'refresh token',
            'scope': 'scope',
          }),
          200,
          headers: {'content-type': 'foo/bar'});

      expect(
          () => handle(response,
              getParameters: (contentType, body) => throw FormatException(
                  'unsupported content-type: $contentType')),
          throwsFormatException);
    });

    test('with a null access token throws a FormatException', () {
      expect(() => handleSuccess(accessToken: null), throwsFormatException);
    });

    test('with a non-string access token throws a FormatException', () {
      expect(() => handleSuccess(accessToken: 12), throwsFormatException);
    });

    test('with a null token type throws a FormatException', () {
      expect(() => handleSuccess(tokenType: null), throwsFormatException);
    });

    test('with a non-string token type throws a FormatException', () {
      expect(() => handleSuccess(tokenType: 12), throwsFormatException);
    });

    test('with a non-"bearer" token type throws a FormatException', () {
      expect(() => handleSuccess(tokenType: 'mac'), throwsFormatException);
    });

    test('with a non-int expires-in throws a FormatException', () {
      expect(() => handleSuccess(expiresIn: 'whenever'), throwsFormatException);
    });

    test(
        'with expires-in sets the expiration to ten seconds earlier than the '
        'server says', () {
      var credentials = handleSuccess(expiresIn: 100);
      expect(credentials.expiration?.millisecondsSinceEpoch,
          startTime.millisecondsSinceEpoch + 90 * 1000);
    });

    test(
        'with refresh-expires-in sets the expiration to ten seconds earlier than'
        ' the server says', () {
      var credentials = handleSuccess(refreshExpiresIn: 100);
      expect(credentials.refreshToKenExpiration?.millisecondsSinceEpoch,
          startTime.millisecondsSinceEpoch + 90 * 1000);
    });

    test('with expires-in encoded as string', () {
      var credentials = handleSuccess(expiresIn: '110');
      expect(credentials.expiration?.millisecondsSinceEpoch,
          startTime.millisecondsSinceEpoch + 100 * 1000);
    });

    test('with expires-in encoded as string', () {
      var credentials = handleSuccess(refreshExpiresIn: '110');
      expect(credentials.refreshToKenExpiration?.millisecondsSinceEpoch,
          startTime.millisecondsSinceEpoch + 100 * 1000);
    });

    test('with a non-string refresh token throws a FormatException', () {
      expect(() => handleSuccess(refreshToken: 12), throwsFormatException);
    });

    test('with a refresh token sets the refresh token', () {
      var credentials = handleSuccess(refreshToken: 'refresh me');
      expect(credentials.refreshToken, equals('refresh me'));
    });

    test('with a non-string scope throws a FormatException', () {
      expect(() => handleSuccess(scope: 12), throwsFormatException);
    });

    test('with a scope sets the scopes', () {
      var credentials = handleSuccess(scope: 'scope1 scope2');
      expect(credentials.scopes, equals(['scope1', 'scope2']));
    });

    test('with a custom scope delimiter sets the scopes', () {
      var response = http.Response(
          jsonEncode({
            'access_token': 'access token',
            'token_type': 'bearer',
            'expires_in': null,
            'refresh_token': null,
            'scope': 'scope1,scope2'
          }),
          200,
          headers: {'content-type': 'application/json'});
      var credentials = handleAccessTokenResponse(
          response, tokenEndpoint, startTime, ['scope'], ',');
      expect(credentials.scopes, equals(['scope1', 'scope2']));
    });
  });

  group('a success response with a id_token', () {
    oauth2.Credentials handleSuccess(
        {String contentType = 'application/json',
        Object? accessToken = 'access token',
        Object? tokenType = 'bearer',
        Object? expiresIn,
        Object? refreshExpiresIn,
        Object? idToken = 'decode me',
        Object? scope}) {
      return handle(http.Response(
          jsonEncode({
            'access_token': accessToken,
            'token_type': tokenType,
            'expires_in': expiresIn,
            'refresh_expires_in': refreshExpiresIn,
            'id_token': idToken,
            'scope': scope
          }),
          200,
          headers: {'content-type': contentType}));
    }

    test('with a non-string id token throws a FormatException', () {
      expect(() => handleSuccess(idToken: 12), throwsFormatException);
    });

    test('with a id token sets the id token', () {
      var credentials = handleSuccess(idToken: 'decode me');
      expect(credentials.idToken, equals('decode me'));
    });
  });
}
