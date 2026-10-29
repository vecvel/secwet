import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/core/bridge.dart';
import 'package:secwet_mobile/core/models.dart';

void main() {
  test('responses unwrap ok and throw structured errors', () {
    expect(decodeResponse('{"ok":42}'), 42);
    expect(
      () => decodeResponse('{"err":{"code":"locked","field":null,"message":"Secwet is locked."}}'),
      throwsA(isA<SecwetException>().having((e) => e.code, 'code', 'locked')),
    );
  });

  test('status, secrets and pairing decode the Rust shapes', () {
    final s = SecwetStatus.fromJson({'status': 'locked', 'secwet_id': 'abc'});
    expect(s.state, LockState.locked);

    final secret = SecretMeta.fromJson({
      'id': 'x',
      'project_id': 'item',
      'environment_id': null,
      'name': 'STRIPE_SECRET_KEY',
      'kind': 'api_key',
      'note': null,
      'updated_at': 1700000000,
      'value_tail': '6789',
    });
    expect(secret.itemId, 'item');
    expect(secret.kind, SecretKind.apiKey);

    final found = PairingPoll.fromJson({
      'status': 'found',
      'name': 'Pixel',
      'platform': 'android',
      'fingerprint': 'AB CD',
      'code': '123456',
      'device_id': 'd1',
    });
    expect(found, isA<PairingFound>().having((f) => f.code, 'code', '123456'));
    expect(PairingPoll.fromJson({'status': 'waiting'}), isA<PairingWaiting>());

    final draft = SecretDraft(itemId: 'i', name: 'N', kind: SecretKind.envVar, value: 'v').toJson();
    expect(draft['kind'], 'env_var');
  });

  test('biometric labels name the phone biometric', () {
    BiometricStatus b(String k) =>
        BiometricStatus.fromJson({'available': true, 'kind': 'fingerprint', 'enabled': true, 'platform_kind': k});
    expect(b('face_id').label, 'Face ID');
    expect(b('face').label, 'face unlock');
    expect(b('fingerprint').label, 'fingerprint');
    expect(b('multiple').label, 'biometrics');
    expect(BiometricStatus.unavailable.available, isFalse);
  });
}
