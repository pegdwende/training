import 'dart:convert';

import 'package:dartz/dartz.dart';
import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:oauth2/oauth2.dart';
import 'package:repo_viewer/auth/domain/auth_failure.dart';
import 'package:repo_viewer/auth/infrastructure/crendential_storage/credential_storage.dart';

import '../core/shared/encoders.dart';

class GithubAuthenticator {
  final CredentialStorage _credentialStorage;

  final Dio _dio;

  GithubAuthenticator(this._credentialStorage, this._dio);

  static final authorizationEndPoint =
      Uri.parse('https://github.com/login/oauth/authorize');

  static final tokenEndPoint =
      Uri.parse("https://github.com/login/oauth/access_token");

  static final redirectUrl = Uri.parse("http://localhost/3000/callback");

  static const clientId = '0f8be83032a7b27a6f1c';

  static final revocationUrl =
      Uri.parse('https://api.github.com/applicaitons/$clientId/token');

  static const clientSecret = 'd49994c68651188b40251b529b7a68f26122a150';

  static const scopes = ['read:user', 'repo'];

  Future<Credentials?> getSignedInCredentials() async {
    try {
      final storedCredentials = await _credentialStorage.read();
      if (storedCredentials != null) {
        if (storedCredentials.canRefresh && storedCredentials.isExpired) {
          //refresh token
        }
        return storedCredentials;
      }
    } on PlatformException {
      return null;
    }
    return null;
  }

  Future<bool> isSignedIn() =>
      getSignedInCredentials().then((credentials) => credentials != null);

  AuthorizationCodeGrant createGrant() {
    return AuthorizationCodeGrant(
      clientId,
      authorizationEndPoint,
      tokenEndPoint,
      secret: clientSecret,
    );
  }

  Uri getAuthorizationUrl(AuthorizationCodeGrant grant) {
    return grant.getAuthorizationUrl(redirectUrl, scopes: scopes);
  }

  Future<Either<AuthFailure, Unit>> handleAuthorizationResponse(
    AuthorizationCodeGrant grant,
    Map<String, String> queryParams,
  ) async {
    try {
      final httpClient = await grant.handleAuthorizationResponse(queryParams);
      await _credentialStorage.save(httpClient.credentials);
      return right(unit);
    } on FormatException {
      return left(const AuthFailure.server());
    } on AuthorizationException catch (e) {
      return left(AuthFailure.server('${e.error}:${e.description}'));
    } on PlatformException {
      return left(const AuthFailure.storage());
    }
  }

  Future<Either<AuthFailure, Unit>> SignOut() async {
    try {
      final accessToken = await _credentialStorage
          .read()
          .then((credentials) => credentials?.accessToken);

      final usernameAndPassword =
          stringToBase64.encode('$clientId:$clientSecret');

      _dio.deleteUri(revocationUrl,
          data: {'access_token': accessToken},
          options: Options(headers: {
            'Authorization': 'basic $usernameAndPassword',
          }));

      await _credentialStorage.clear();
      right(unit);
    } on PlatformException {
      return left(const AuthFailure.storage());
    }
  }
}
