// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:test/test.dart';

import 'utils.dart';

final Uri tokenEndpoint = Uri.parse('http://example.com/token');

void main() {
  late ExpectClient httpClient;

  setUp(() => httpClient = ExpectClient());

  test('is not expired if no expiration exists', () {
    var credentials = oauth2.Credentials('access token');
    expect(credentials.isExpired, isFalse);
  });

  test('is not expired if no expiration exists', () {
    var credentials =
        oauth2.Credentials('access token', refreshToken: 'refresh token');
    expect(credentials.isRefreshTokenExpired, isFalse);
  });

  test('is not expired if the accessExpiration is in the future', () {
    var expiration = DateTime.now().add(const Duration(hours: 1));
    var credentials =
        oauth2.Credentials('access token', expiration: expiration);
    expect(credentials.isExpired, isFalse);
  });

  test('is not expired if the refreshExpiration is in the future', () {
    var expiration = DateTime.now().add(const Duration(hours: 1));
    var credentials =
        oauth2.Credentials('access token', refreshToKenExpiration: expiration);
    expect(credentials.isRefreshTokenExpired, isFalse);
  });

  test('is expired if the expiration is in the past', () {
    var expiration = DateTime.now().subtract(const Duration(hours: 1));
    var credentials =
        oauth2.Credentials('access token', expiration: expiration);
    expect(credentials.isExpired, isTrue);
  });

  test('is expired if the refreshExpiration is in the past', () {
    var expiration = DateTime.now().subtract(const Duration(hours: 1));
    var credentials =
        oauth2.Credentials('access token', refreshToKenExpiration: expiration);
    expect(credentials.isRefreshTokenExpired, isTrue);
  });

  test("can't refresh without a refresh token", () {
    var credentials =
        oauth2.Credentials('access token', tokenEndpoint: tokenEndpoint);
    expect(credentials.canRefresh, false);

    expect(
        credentials.refresh(
            identifier: 'identifier', secret: 'secret', httpClient: httpClient),
        throwsStateError);
  });

  test("can't refresh without a token endpoint", () {
    var credentials =
        oauth2.Credentials('access token', refreshToken: 'refresh token');
    expect(credentials.canRefresh, false);

    expect(
        credentials.refresh(
            identifier: 'identifier', secret: 'secret', httpClient: httpClient),
        throwsStateError);
  });

  test('can refresh with a refresh token and a token endpoint', () async {
    var credentials = oauth2.Credentials('access token',
        refreshToken: 'refresh token',
        tokenEndpoint: tokenEndpoint,
        scopes: ['scope1', 'scope2']);
    expect(credentials.canRefresh, true);

    httpClient.expectRequest((request) {
      expect(request.method, equals('POST'));
      expect(request.url.toString(), equals(tokenEndpoint.toString()));
      expect(
          request.bodyFields,
          equals({
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh token',
            'scope': 'scope1 scope2'
          }));
      expect(
          request.headers,
          containsPair('Authorization',
              'Basic aWQlQzMlQUJudCVDNCVBQmZpZXI6cyVDMyVBQmNyZXQ='));

      return Future.value(http.Response(
          jsonEncode({
            'access_token': 'new access token',
            'token_type': 'bearer',
            'refresh_token': 'new refresh token'
          }),
          200,
          headers: {'content-type': 'application/json'}));
    });

    credentials = await credentials.refresh(
        identifier: 'idëntīfier', secret: 'sëcret', httpClient: httpClient);
    expect(credentials.accessToken, equals('new access token'));
    expect(credentials.refreshToken, equals('new refresh token'));
  });

  test('sets proper scope string when using custom delimiter', () async {
    var credentials = oauth2.Credentials('access token',
        refreshToken: 'refresh token',
        tokenEndpoint: tokenEndpoint,
        scopes: ['scope1', 'scope2'],
        delimiter: ',');
    httpClient.expectRequest((http.Request request) {
      expect(request.bodyFields['scope'], equals('scope1,scope2'));
      return Future.value(http.Response(
          jsonEncode({
            'access_token': 'new access token',
            'token_type': 'bearer',
            'refresh_token': 'new refresh token'
          }),
          200,
          headers: {'content-type': 'application/json'}));
    });
    await credentials.refresh(
        identifier: 'idëntīfier', secret: 'sëcret', httpClient: httpClient);
  });

  test('can refresh without a client secret', () async {
    var credentials = oauth2.Credentials('access token',
        refreshToken: 'refresh token',
        tokenEndpoint: tokenEndpoint,
        scopes: ['scope1', 'scope2']);
    expect(credentials.canRefresh, true);

    httpClient.expectRequest((request) {
      expect(request.method, equals('POST'));
      expect(request.url.toString(), equals(tokenEndpoint.toString()));
      expect(
          request.bodyFields,
          equals({
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh token',
            'scope': 'scope1 scope2',
            'client_id': 'identifier'
          }));

      return Future.value(http.Response(
          jsonEncode({
            'access_token': 'new access token',
            'token_type': 'bearer',
            'refresh_token': 'new refresh token'
          }),
          200,
          headers: {'content-type': 'application/json'}));
    });

    credentials = await credentials.refresh(
        identifier: 'identifier', httpClient: httpClient);
    expect(credentials.accessToken, equals('new access token'));
    expect(credentials.refreshToken, equals('new refresh token'));
  });

  test('can refresh without client authentication', () async {
    var credentials = oauth2.Credentials('access token',
        refreshToken: 'refresh token',
        tokenEndpoint: tokenEndpoint,
        scopes: ['scope1', 'scope2']);
    expect(credentials.canRefresh, true);

    httpClient.expectRequest((request) {
      expect(request.method, equals('POST'));
      expect(request.url.toString(), equals(tokenEndpoint.toString()));
      expect(
          request.bodyFields,
          equals({
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh token',
            'scope': 'scope1 scope2'
          }));

      return Future.value(http.Response(
          jsonEncode({
            'access_token': 'new access token',
            'token_type': 'bearer',
            'refresh_token': 'new refresh token'
          }),
          200,
          headers: {'content-type': 'application/json'}));
    });

    credentials = await credentials.refresh(httpClient: httpClient);
    expect(credentials.accessToken, equals('new access token'));
    expect(credentials.refreshToken, equals('new refresh token'));
  });

  test("uses the old refresh token if a new one isn't provided", () async {
    var credentials = oauth2.Credentials('access token',
        refreshToken: 'refresh token', tokenEndpoint: tokenEndpoint);
    expect(credentials.canRefresh, true);

    httpClient.expectRequest((request) {
      expect(request.method, equals('POST'));
      expect(request.url.toString(), equals(tokenEndpoint.toString()));
      expect(
          request.bodyFields,
          equals({
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh token'
          }));
      expect(
          request.headers,
          containsPair('Authorization',
              'Basic aWQlQzMlQUJudCVDNCVBQmZpZXI6cyVDMyVBQmNyZXQ='));

      return Future.value(http.Response(
          jsonEncode(
              {'access_token': 'new access token', 'token_type': 'bearer'}),
          200,
          headers: {'content-type': 'application/json'}));
    });

    credentials = await credentials.refresh(
        identifier: 'idëntīfier', secret: 'sëcret', httpClient: httpClient);
    expect(credentials.accessToken, equals('new access token'));
    expect(credentials.refreshToken, equals('refresh token'));
  });

  test('uses form-field authentication if basicAuth is false', () async {
    var credentials = oauth2.Credentials('access token',
        refreshToken: 'refresh token',
        tokenEndpoint: tokenEndpoint,
        scopes: ['scope1', 'scope2']);
    expect(credentials.canRefresh, true);

    httpClient.expectRequest((request) {
      expect(request.method, equals('POST'));
      expect(request.url.toString(), equals(tokenEndpoint.toString()));
      expect(
          request.bodyFields,
          equals({
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh token',
            'scope': 'scope1 scope2',
            'client_id': 'idëntīfier',
            'client_secret': 'sëcret'
          }));

      return Future.value(http.Response(
          jsonEncode({
            'access_token': 'new access token',
            'token_type': 'bearer',
            'refresh_token': 'new refresh token'
          }),
          200,
          headers: {'content-type': 'application/json'}));
    });

    credentials = await credentials.refresh(
        identifier: 'idëntīfier',
        secret: 'sëcret',
        basicAuth: false,
        httpClient: httpClient);
    expect(credentials.accessToken, equals('new access token'));
    expect(credentials.refreshToken, equals('new refresh token'));
  });

  group('fromJson', () {
    oauth2.Credentials fromMap(Map<String, dynamic> map) =>
        oauth2.Credentials.fromJson(jsonEncode(map));

    test('should load the same credentials from toJson', () {
      // Round the expiration down to milliseconds since epoch, since that's
      // what the credentials file stores. Otherwise sub-millisecond time gets
      // in the way.
      var expiration = DateTime.now().subtract(const Duration(hours: 1));
      expiration = DateTime.fromMillisecondsSinceEpoch(
          expiration.millisecondsSinceEpoch);
      var refreshExpiration = DateTime.now();
      refreshExpiration = DateTime.fromMillisecondsSinceEpoch(
          refreshExpiration.millisecondsSinceEpoch);

      var credentials = oauth2.Credentials(
        'access token',
        refreshToken: 'refresh token',
        idToken: 'id token',
        tokenEndpoint: tokenEndpoint,
        scopes: ['scope1', 'scope2'],
        expiration: expiration,
        refreshToKenExpiration: refreshExpiration,
      );
      var reloaded = oauth2.Credentials.fromJson(credentials.toJson());

      expect(reloaded.accessToken, equals(credentials.accessToken));
      expect(reloaded.refreshToken, equals(credentials.refreshToken));
      expect(reloaded.idToken, equals(credentials.idToken));
      expect(reloaded.tokenEndpoint.toString(),
          equals(credentials.tokenEndpoint.toString()));
      expect(reloaded.scopes, equals(credentials.scopes));
      expect(reloaded.expiration, equals(credentials.expiration));
      expect(reloaded.refreshToKenExpiration,
          equals(credentials.refreshToKenExpiration));
    });

    test('should throw a FormatException for invalid JSON', () {
      expect(
          () => oauth2.Credentials.fromJson('foo bar'), throwsFormatException);
    });

    test("should throw a FormatException for JSON that's not a map", () {
      expect(() => oauth2.Credentials.fromJson('null'), throwsFormatException);
    });

    test('should throw a FormatException if there is no accessToken', () {
      expect(() => fromMap({}), throwsFormatException);
    });

    test('should throw a FormatException if accessToken is not a string', () {
      expect(() => fromMap({'accessToken': 12}), throwsFormatException);
    });

    test('should throw a FormatException if refreshToken is not a string', () {
      expect(() => fromMap({'accessToken': 'foo', 'refreshToken': 12}),
          throwsFormatException);
    });

    test('should throw a FormatException if idToken is not a string', () {
      expect(() => fromMap({'accessToken': 'foo', 'idToken': 12}),
          throwsFormatException);
    });

    test('should throw a FormatException if tokenEndpoint is not a string', () {
      expect(() => fromMap({'accessToken': 'foo', 'tokenEndpoint': 12}),
          throwsFormatException);
    });

    test('should throw a FormatException if scopes is not a list', () {
      expect(() => fromMap({'accessToken': 'foo', 'scopes': 12}),
          throwsFormatException);
    });

    test('should throw a FormatException if expiration is not an int', () {
      expect(() => fromMap({'accessToken': 'foo', 'expiration': '12'}),
          throwsFormatException);
    });
  });
}
