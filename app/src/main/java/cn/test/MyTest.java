package cn.test;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.KeyCrypterScrypt;

import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.FixedPointUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Asa on 2018/3/2.
 */

public class MyTest {
    public static void generateAccount(SecureRandom secureRandom) {
        X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
        FixedPointUtil.precompute(CURVE_PARAMS.getG(), 12);
        ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());

        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        generator.init(keygenParams);

        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();

        BigInteger priv = privParams.getD();
        boolean compressed = true;
        byte[] pubKey = pubParams.getQ().getEncoded(compressed);
    }

    public static void encryptECKey(ECKey key, CharSequence password) {
        KeyCrypterScrypt scrypt = new KeyCrypterScrypt();

        KeyParameter derivedKey = scrypt.deriveKey(password);

        ECKey encryptedKey = key.encrypt(scrypt, derivedKey);

        boolean reversible = ECKey.encryptionIsReversible(key, encryptedKey, scrypt, derivedKey);
    }
}
