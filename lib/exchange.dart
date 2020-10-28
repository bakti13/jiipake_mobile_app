import 'dart:collection';
import 'dart:math';
import 'package:crypto/crypto.dart';

class Exchange {
  static const String CLIENTID = "Bob";
  static const String SERVERID = "Alice";
  static const int PORT = 1234;
  static final BigInt P = BigInt.parse(
      "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",
      radix: 16);
  static final BigInt Q =
      BigInt.parse("9760508f15230bccb292b982a2eb840bf0581cf5", radix: 16);
  static final BigInt G = BigInt.parse(
      "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",
      radix: 16);

  static String secureRandom() {
    var rng = Random();
    String str = (1 + rng.nextInt(9)).toString();
    for (var i = 1; i < (47 + rng.nextInt(2)); i++) {
      str += rng.nextInt(10).toString();
    }
    return str;
  }

  List<String> generateZKP(
      BigInt p, BigInt q, BigInt g, BigInt gx, BigInt x, String signerID) {
    List<String> ZKP = List(2); // ignore: non_constant_identifier_names

    /* Generate a random v, and compute g^v */
    BigInt v = BigInt.parse(secureRandom(), radix: 10);
    BigInt gv = g.modPow(v, p);
    BigInt h = getSHA1(g, gv, gx, signerID); // h

    ZKP[0] = gv.toString();
    ZKP[1] = ((v - (x * h)) % q).toString(); // r = v-x*h

    return ZKP;
  }

  BigInt getSHA1(BigInt g, BigInt gr, BigInt gx, String signerID) {
    return BigInt.tryParse((sha1.convert(signerID.codeUnits)).toString(),
            radix: 16) +
        getSHA1Key(g + gr + gx);
  }

  BigInt getSHA1Key(BigInt K) {
    return BigInt.tryParse((sha1.convert(K.toString().codeUnits)).toString(),
        radix: 16);
  }

  bool verifyZKP(BigInt p, BigInt q, BigInt g, BigInt gx, List<BigInt> sig,
      String signerID) {
    /* sig={g^v,r} */
    BigInt h = getSHA1(g, sig[0], gx, signerID);
    return ((gx.compareTo(BigInt.zero) >= 1) && // g^x > 0
        (gx.compareTo(p - BigInt.one) <= -1) && // g^x < p-1
        (gx.modPow(q, p).compareTo(BigInt.one) == 0) && // g^x^q = 1
        /* Below, I took an straightforward way to compute g^r * g^x^h, which needs 2 exp. Using
    			 * a simultaneous computation technique would only need 1 exp.
    			 */
        ((g.modPow(sig[1], p) * gx.modPow(h, p)) % p).compareTo(sig[0]) ==
            0); // g^v=g^r * g^x^h
  }

  BigInt getSessionKeys(BigInt gx1, BigInt x1, BigInt x, BigInt s1) {
    return getSHA1Key((gx1.modPow((-(x1 * s1)) % Q, P) * x).modPow(x1, P));
  }

  /// Step 1.a: Alice sends g^{x1}, g^{x2}, and Bob sends g^{x3}, g^{x4}
  Map<String, dynamic> roundOne(BigInt x1, BigInt x2, String id) {
    HashMap<String, dynamic> result = new HashMap();

    BigInt gx1 = G.modPow(x1, P);
    BigInt gx2 = G.modPow(x2, P);
    List<String> sigX1 = generateZKP(P, Q, G, gx1, x1, CLIENTID);
    List<String> sigX2 = generateZKP(P, Q, G, gx2, x2, CLIENTID);

    result.putIfAbsent("gx3", () => gx1.toString());
    result.putIfAbsent("gx4", () => gx2.toString());
    result.putIfAbsent("ZKP3", () => sigX1);
    result.putIfAbsent("ZKP4", () => sigX2);

    return result;
  }

  /// Step 1.b Bob/Client Verifies ZKP from Alice/Server
  bool cekZKP(BigInt gx1, BigInt gx2, List<BigInt> sigX1, List<BigInt> sigX2) {
    return (gx2 == BigInt.one ||
        !verifyZKP(P, Q, G, gx1, sigX1, CLIENTID) ||
        !verifyZKP(P, Q, G, gx2, sigX2, CLIENTID));
  }

  /// Step 2.a: Alice sends A and Bob sends B
  Map<String, dynamic> roundTwo(
      BigInt gx1, BigInt gx2, BigInt gx3, BigInt x1, BigInt s1) {
    HashMap<String, Object> result = new HashMap();
    BigInt gX = gx1 * gx2 * gx3 % P;
    BigInt x = gX.modPow(x1 * s1 % Q, P);
    List<String> sigXs = generateZKP(P, Q, gX, x, x1 * s1 % Q, CLIENTID);
    result.putIfAbsent("B", () => x.toString());
    result.putIfAbsent("gB", () => gX.toString());
    result.putIfAbsent("KP{x4*s}", () => sigXs);
    return result;
  }

  /// Step 2.b Bob/Client checks KP{x2*s} from Alice/Server
  /// Bob verifies Alice's ZKP => KP{x2*s}
  bool chekZKPs(BigInt gX, BigInt x, List<BigInt> sigXs) {
    return verifyZKP(P, Q, gX, x, sigXs, SERVERID);
  }
}
