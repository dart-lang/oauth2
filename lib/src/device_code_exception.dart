// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// An exception raised when [DeviceAuthorizationGrant] fails.
/// This exception is thrown when the client cannot get a device code from the
/// server for several reasons
class DeviceException implements Exception {
  /// The name of the error.
  ///
  /// Possible names are enumerated in [the spec][].
  ///
  /// [the spec]: http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-5.2
  final String error;

  /// The description of the error, provided by the server.
  ///
  /// May be `null` if the server provided no description.
  final String? description;

  /// A URL for a page that describes the error in more detail, provided by the
  /// server.
  ///
  /// May be `null` if the server provided no URL.
  final Uri? uri;

  /// Creates an DeviceException.
  DeviceException(this.error, this.description, this.uri);

  /// Provides a string description of the AuthorizationException.
  @override
  String toString() {
    var header = 'OAuth device error ($error)';
    if (description != null) {
      header = '$header: $description';
    } else if (uri != null) {
      header = '$header: $uri';
    }
    return '$header.';
  }
}
