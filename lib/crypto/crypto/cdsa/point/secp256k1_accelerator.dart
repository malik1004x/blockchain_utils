import 'package:blockchain_utils/crypto/crypto/cdsa/curve/curve.dart';

/// Optional faster secp256k1 arithmetic, e.g. backed by a native library.
///
/// Implementations must return exactly what the pure Dart code computes, or null whenever they
/// can't, in which case the pure Dart code runs as before. [instance] is per isolate.
abstract class Secp256k1Accelerator {
  static Secp256k1Accelerator? instance;

  static final BigInt _p =
      BigInt.parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", radix: 16);
  static final BigInt _seven = BigInt.from(7);

  static final BigInt order =
      BigInt.parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16);
  static final BigInt generatorX =
      BigInt.parse("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", radix: 16);
  static final BigInt generatorY =
      BigInt.parse("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", radix: 16);

  static bool isSecp256k1(CurveFp curve) =>
      curve.p == _p && curve.a == BigInt.zero && curve.b == _seven && curve.h == BigInt.one;

  /// [scalar] (32 bytes big-endian, in [1, n)) times [point] (65-byte uncompressed SEC1, null for
  /// the generator), as a 65-byte uncompressed SEC1 point.
  List<int>? multiply(List<int>? point, List<int> scalar);

  /// The 65-byte uncompressed SEC1 form of a 33-byte compressed point.
  List<int>? decompress(List<int> compressed);
}
