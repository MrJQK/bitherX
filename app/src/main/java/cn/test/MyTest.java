package cn.test;

import com.lambdaworks.crypto.SCrypt;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.KeyCrypterScrypt;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.annotation.Nullable;

/**
 * Created by Asa on 2018/3/2.
 */

public class MyTest {
    /**************************************/
    //  生成普通账户（密钥对）
    /**************************************/
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

    public static void deriveKey(CharSequence password){
          final int BITCOINJ_SCRYPT_N = 16384;
          final int BITCOINJ_SCRYPT_R = 8;
          final int BITCOINJ_SCRYPT_P = 1;
          final int KEY_LENGTH = 32; // = 256 bits.

        byte[] passwordBytes = null;
        byte[] salt = new byte[0];

        try {
            byte[] keyBytes = SCrypt.scrypt(passwordBytes, salt, BITCOINJ_SCRYPT_N, BITCOINJ_SCRYPT_R, BITCOINJ_SCRYPT_P, KEY_LENGTH);

            new KeyParameter(keyBytes);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static void encryptedKey(ECKey key, KeyParameter derivedKey ,KeyCrypterScrypt scrypt ){
        final byte[] privKeyBytes =key.getPrivKeyBytes();

    }

    /**
     * 地址
     * */
    public static void getAddress(byte[] pub){
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(pub);

            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(sha256, 0, sha256.length);

            byte[] pubKeyHash = new byte[20];
            digest.doFinal(pubKeyHash, 0);

            int version = 0;// BitherjSettings.addressHeader;
            byte[] addressBytes = new byte[1 + pubKeyHash.length + 4];
            addressBytes[0] = (byte) version;

            System.arraycopy(pubKeyHash, 0, addressBytes, 1, pubKeyHash.length);

            MessageDigest mdigest = MessageDigest.getInstance("SHA-256");
            mdigest.reset();
            mdigest.update(addressBytes, 0, pubKeyHash.length+1);
            byte[] first = mdigest.digest();
            byte[] check = mdigest.digest(first);

            System.arraycopy(check, 0, addressBytes, pubKeyHash.length + 1, 4);

            Base58.encode(addressBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    /**
     * 私钥——》公钥
     * */
    public static void publicKeyFromPrivate(BigInteger privKey){
        X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
        FixedPointUtil.precompute(CURVE_PARAMS.getG(), 12);
        ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());

        ECPoint point = CURVE.getG().multiply(privKey);

        // 压缩
        point = CURVE.getCurve().decodePoint(point.getEncoded(true));

        byte[] publicKey =  point.getEncoded();
    }

    /**
     * 签名
     * */
    public static void signMessage(String message, CharSequence passphrase){
        // passphrase\address --> ECKey
        ECKey  key=null;

        KeyParameter assKey = key.getKeyCrypter().deriveKey(passphrase);

       //: String result = key.signMessage(msg, assKey);
        byte[] data = Utils.formatMessageForSigning(message);
        byte[] hash = Utils.doubleDigest(data);

        // The private key bytes to use for signing.
        BigInteger privateKeyForSigning;

//        if (isEncrypted()) {
//            // The private key needs decrypting before use.
//            if (aesKey == null) {
//                throw new KeyCrypterException("This ECKey is encrypted but no decryption key has been supplied.");
//            }
//
//            if (keyCrypter == null) {
//                throw new KeyCrypterException("There is no KeyCrypter to decrypt the private key for signing.");
//            }
//
//            privateKeyForSigning = new BigInteger(1, keyCrypter.decrypt(encryptedPrivateKey, aesKey));
//            // Check encryption was correct.
//            if (!Arrays.equals(pub, publicKeyFromPrivate(privateKeyForSigning, isCompressed())))
//                throw new KeyCrypterException("Could not decrypt bytes");
//        } else {
//            // No decryption of private key required.
//            if (priv == null) {
//                throw new KeyCrypterException("This ECKey does not have the private key necessary for signing.");
//            } else {
//                privateKeyForSigning = priv;
//            }
//        }
//
//        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
//        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
//        signer.init(true, privKey);
//        BigInteger[] components = signer.generateSignature(input);
//        final ECKey.ECDSASignature signature = new ECKey.ECDSASignature(components[0], components[1]);
//        signature.ensureCanonical();
    }


//    public byte[] signHash(byte[] hash, @Nullable KeyParameter aesKey) throws KeyCrypterException {
//        ECKey.ECDSASignature sig = sign(hash, aesKey);
//        // Now we have to work backwards to figure out the recId needed to recover the signature.
//        int recId = -1;
//        for (int i = 0; i < 4; i++) {
//            ECKey k = ECKey.recoverFromSignature(i, sig, hash, isCompressed());
//            if (k != null && Arrays.equals(k.pub, pub)) {
//                recId = i;
//                break;
//            }
//        }
//        if (recId == -1)
//            throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
//        int headerByte = recId + 27 + (isCompressed() ? 4 : 0);
//        byte[] sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
//        sigData[0] = (byte) headerByte;
//        System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32), 0, sigData, 1, 32);
//        System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32), 0, sigData, 33, 32);
//        return sigData;
//    }

}
