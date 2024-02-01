// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:test/test.dart';

import 'utils.dart';

final Uri requestUri = Uri.parse('http://example.com/resource');

final Uri tokenEndpoint = Uri.parse('http://example.com/token');

void main() {
  late ExpectClient httpClient;

  setUp(() => httpClient = ExpectClient());

  group('with expired credentials', () {
    test("that can't be refreshed throws an ExpirationException on send", () {
      var expiration = DateTime.now().subtract(const Duration(hours: 1));
      var credentials =
          oauth2.Credentials('access token', expiration: expiration);
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      expect(client.get(requestUri),
          throwsA(const TypeMatcher<oauth2.ExpirationException>()));
    });

    test(
        'that can be refreshed refreshes the credentials and sends the '
        'request', () async {
      var expiration = DateTime.now().subtract(const Duration(hours: 1));
      var credentials = oauth2.Credentials('access token',
          refreshToken: 'refresh token',
          tokenEndpoint: tokenEndpoint,
          expiration: expiration);
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(tokenEndpoint.toString()));
        return Future.value(http.Response(
            jsonEncode(
                {'access_token': 'new access token', 'token_type': 'bearer'}),
            200,
            headers: {'content-type': 'application/json'}));
      });

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'],
            equals('Bearer new access token'));

        return Future.value(http.Response('good job', 200));
      });

      await client.read(requestUri);
      expect(client.credentials.accessToken, equals('new access token'));
    });

    test(
      'that can be refreshed refreshes only once if multiple requests are made',
      () async {
        var expiration = DateTime.now().subtract(const Duration(hours: 1));
        var credentials = oauth2.Credentials('access token',
            refreshToken: 'refresh token',
            tokenEndpoint: tokenEndpoint,
            expiration: expiration);
        var client = oauth2.Client(credentials,
            identifier: 'identifier', secret: 'secret', httpClient: httpClient);

        httpClient.expectRequest((request) {
          expect(request.method, equals('POST'));
          expect(request.url.toString(), equals(tokenEndpoint.toString()));
          return Future.value(http.Response(
              jsonEncode(
                  {'access_token': 'new access token', 'token_type': 'bearer'}),
              200,
              headers: {'content-type': 'application/json'}));
        });

        const numCalls = 2;

        for (var i = 0; i < numCalls; i++) {
          httpClient.expectRequest((request) {
            expect(request.method, equals('GET'));
            expect(request.url.toString(), equals(requestUri.toString()));
            expect(request.headers['authorization'],
                equals('Bearer new access token'));

            return Future.value(http.Response('good job', 200));
          });
        }

        await Future.wait(
          List<Future<String>>.generate(
              numCalls, (_) => client.read(requestUri)),
        );

        expect(client.credentials.accessToken, equals('new access token'));
      },
    );

    test('that onCredentialsRefreshed is called', () async {
      var callbackCalled = false;

      var expiration = DateTime.now().subtract(const Duration(hours: 1));
      var credentials = oauth2.Credentials('access token',
          refreshToken: 'refresh token',
          tokenEndpoint: tokenEndpoint,
          expiration: expiration);
      var client = oauth2.Client(credentials,
          identifier: 'identifier',
          secret: 'secret',
          httpClient: httpClient, onCredentialsRefreshed: (credentials) {
        callbackCalled = true;
        expect(credentials.accessToken, equals('new access token'));
      });

      httpClient.expectRequest(
        (request) => Future.value(
          http.Response(
            jsonEncode(
              {'access_token': 'new access token', 'token_type': 'bearer'},
            ),
            200,
            headers: {'content-type': 'application/json'},
          ),
        ),
      );

      httpClient.expectRequest(
          (request) => Future.value(http.Response('good job', 200)));

      await client.read(requestUri);
      expect(callbackCalled, equals(true));
    });
  });

  group('with valid credentials', () {
    test('sends a request with bearer authorization', () {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'], equals('Bearer access token'));

        return Future.value(http.Response('good job', 200));
      });

      expect(client.read(requestUri), completion(equals('good job')));
    });

    test('can manually refresh the credentials', () async {
      var credentials = oauth2.Credentials('access token',
          refreshToken: 'refresh token', tokenEndpoint: tokenEndpoint);
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(tokenEndpoint.toString()));
        return Future.value(http.Response(
            jsonEncode(
                {'access_token': 'new access token', 'token_type': 'bearer'}),
            200,
            headers: {'content-type': 'application/json'}));
      });

      await client.refreshCredentials();
      expect(client.credentials.accessToken, equals('new access token'));
    });

    test("without a refresh token can't manually refresh the credentials", () {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      expect(client.refreshCredentials(), throwsA(isStateError));
    });

    test("won't send a request with closed client", () {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      expect(client.isClosed, equals(false));

      client.close();

      expect(client.isClosed, equals(true));

      expect(client.read(requestUri),
          throwsA(const TypeMatcher<http.ClientException>()));
    });
  });

  group('with invalid credentials', () {
    test('throws an AuthorizationException for a 401 response', () {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'], equals('Bearer access token'));

        var authenticate = 'Bearer error="invalid_token", error_description='
            '"Something is terribly wrong."';
        return Future.value(http.Response('bad job', 401,
            headers: {'www-authenticate': authenticate}));
      });

      expect(client.read(requestUri),
          throwsA(const TypeMatcher<oauth2.AuthorizationException>()));
    });

    test('passes through a 401 response without www-authenticate', () async {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'], equals('Bearer access token'));

        return Future.value(http.Response('bad job', 401));
      });

      expect((await client.get(requestUri)).statusCode, equals(401));
    });

    test('passes through a 401 response with invalid www-authenticate',
        () async {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'], equals('Bearer access token'));

        var authenticate = 'Bearer error="invalid_token" error_description='
            '"Something is terribly wrong."';
        return Future.value(http.Response('bad job', 401,
            headers: {'www-authenticate': authenticate}));
      });

      expect((await client.get(requestUri)).statusCode, equals(401));
    });

    test('passes through a 401 response with non-bearer www-authenticate',
        () async {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'], equals('Bearer access token'));

        return Future.value(http.Response('bad job', 401,
            headers: {'www-authenticate': 'Digest'}));
      });

      expect((await client.get(requestUri)).statusCode, equals(401));
    });

    test('passes through a 401 response with non-OAuth2 www-authenticate',
        () async {
      var credentials = oauth2.Credentials('access token');
      var client = oauth2.Client(credentials,
          identifier: 'identifier', secret: 'secret', httpClient: httpClient);

      httpClient.expectRequest((request) {
        expect(request.method, equals('GET'));
        expect(request.url.toString(), equals(requestUri.toString()));
        expect(request.headers['authorization'], equals('Bearer access token'));

        return Future.value(http.Response('bad job', 401,
            headers: {'www-authenticate': 'Bearer'}));
      });

      expect((await client.get(requestUri)).statusCode, equals(401));
    });
  });
}
