package com.github.mperever.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Represents utility to encrypt and decrypt data using AES256 and HMAC.
 *
 * @author mperever
 *
 */
public class AesEncryptionUtils
{
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String AES_KEY_ALGORITHM = "AES";
    private static final int AES_KEY_SIZE = 32; // in bytes (256 bits)
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int INIT_VECTOR_SIZE = 16; // in bytes (128 bits)
    private static final int HMAC_KEY_SIZE = 32; // in bytes (256 bits)
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Charset CHARSET_ENCODING = StandardCharsets.UTF_8;

    private AesEncryptionUtils()
    {
    }

    /**
     * Generates private AES Key.
     *
     * @return AES Key bytes
     * @throws AesEncryptionException if AES algorithm is not found.
     */
    public static byte[] getAesKey() throws AesEncryptionException
    {
        try
        {
            final KeyGenerator keyGen = KeyGenerator.getInstance( AES_KEY_ALGORITHM );
            keyGen.init( AES_KEY_SIZE * 8 ); // value in bits
            return keyGen.generateKey().getEncoded();

        } catch ( NoSuchAlgorithmException ex )
        {
            throw new AesEncryptionException( ex );
        }
    }

    /**
     * Generates public initialization vector.
     *
     * @return Random initialization vector bytes
     * @throws AesEncryptionException if random algorithm is not found
     */
    public static byte[] getIv() throws AesEncryptionException
    {
        return getRandomKey( INIT_VECTOR_SIZE );
    }

    /**
     * Generates private HMAC key.
     *
     * @return Random HMAC key bytes
     * @throws AesEncryptionException if random algorithm is not found
     */
    public static byte[] getHmacKey() throws AesEncryptionException
    {
        return getRandomKey( HMAC_KEY_SIZE );
    }

    /**
     * Generate HMAC for the specified source and HMAC key.
     *
     * @param source The target source for generation
     * @param hmacKey HMAC key
     * @return HMAC bytes for source
     * @throws AesEncryptionException if HMAC algorithm is not found
     *     or given HMAC algorithm parameters are inappropriate for this MAC.
     */
    public static byte[] getHmac( byte[] source, byte[] hmacKey ) throws AesEncryptionException
    {
        final SecretKeySpec keySpec = new SecretKeySpec( hmacKey, HMAC_ALGORITHM );
        try
        {
            final Mac hmac = Mac.getInstance( HMAC_ALGORITHM );
            hmac.init( keySpec );
            return hmac.doFinal( source );

        } catch ( NoSuchAlgorithmException | InvalidKeyException ex )
        {
            throw new AesEncryptionException( ex );
        }
    }

    /**
     * Encrypts source bytes with specified AES Key and initialization vector.
     *
     * @param source The source for encryption
     * @param initVector Public initialization vector
     * @param privateData private information for encryption
     * @return public information with encrypted source
     * @throws AesEncryptionException if an error occurs during encryptions
     */
    public static EncryptedPublicData encrypt( byte[] source,
                                               byte[] initVector,
                                               final EncryptedPrivateData privateData )
            throws AesEncryptionException
    {
        final SecretKey key = getAesSecretKey( privateData.getAesKey() );
        final IvParameterSpec ivSpec = new IvParameterSpec( initVector );

        try
        {
            // Encrypt source bytes
            final Cipher cp = Cipher.getInstance( CIPHER_TRANSFORMATION );
            cp.init( Cipher.ENCRYPT_MODE, key, ivSpec );
            final byte[] encryptedSource = cp.doFinal( source );

            // Get HMAC for source
            final byte[] hmac = getHmac( encryptedSource, privateData.getHmacKey() );

            // Create public data
            return new EncryptedPublicData( encryptedSource, initVector, hmac );

        } catch ( NoSuchAlgorithmException
                | InvalidKeyException
                | InvalidAlgorithmParameterException
                | BadPaddingException
                | NoSuchPaddingException
                | IllegalBlockSizeException ex )
        {
            throw new AesEncryptionException( ex );
        }
    }

    public static EncryptedPublicData encrypt( byte[] source,
                                               final EncryptedPrivateData privateData )
            throws AesEncryptionException
    {
        final byte[] initVector = getIv();
        return encrypt( source, initVector, privateData );
    }

    /**
     * Encrypt the specified text.
     * Encryption private keys will be generated automatically.
     *
     * @param text The text for encryption
     * @return Combination of private encryption data and public one.
     * @throws AesEncryptionException if an error occurs during encryption.
     */
    public static EncryptedData encryptText( String text ) throws AesEncryptionException
    {
        final byte[] aesKey = getAesKey();
        final byte[] hmacKey = getHmacKey();
        final EncryptedPrivateData privateData = new EncryptedPrivateData( aesKey, hmacKey );

        // Encrypt source text with generated private data
        final EncryptedPublicData publicData =
                encrypt( text.getBytes( CHARSET_ENCODING ), privateData );

        return new EncryptedData( publicData, privateData );
    }

    /**
     * Encrypt the text with specified private keys.
     *
     * @param text The text for encryption
     * @param privateData The private keys
     * @return Encrypted public data
     * @throws AesEncryptionException if an error occurs during encryption.
     */
    public static EncryptedPublicData encryptText( String text,
                                                   final EncryptedPrivateData privateData )
            throws AesEncryptionException
    {
        return encrypt( text.getBytes( CHARSET_ENCODING ), privateData );
    }

    /**
     * Decrypts encrypted source with specified AES Key, initialization vector,
     * HMAC for encrypted source and HMAC key.
     *
     * @param publicData public information for decryption
     * @param privateData private information for decryption
     * @return Decrypted source
     * @throws AesEncryptionException if an error occurs during decryption
     */
    public static byte[] decrypt( final EncryptedPublicData publicData,
                                  final EncryptedPrivateData privateData )
            throws AesEncryptionException
    {

        final byte[] source = publicData.getEncryptedData();
        final byte[] hmac = publicData.getHmac();
        final byte[] initVector = publicData.getInitVector();

        final byte[] aesKey = privateData.getAesKey();
        final byte[] hmacKey = privateData.getHmacKey();

        try
        {
            checkSourceHmac( source, hmac, hmacKey );

            final SecretKey key = getAesSecretKey( aesKey );
            final IvParameterSpec ivSpec = new IvParameterSpec( initVector );

            final Cipher cp = Cipher.getInstance( CIPHER_TRANSFORMATION );
            cp.init( Cipher.DECRYPT_MODE, key, ivSpec );
            return cp.doFinal( source );

        } catch ( NoSuchAlgorithmException
                | InvalidKeyException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | BadPaddingException
                | IllegalBlockSizeException ex )
        {
            throw new AesEncryptionException( ex );
        }
    }

    /**
     * Decrypt the text using specified private keys.
     *
     * @param encryptedText The text for decryption
     * @param privateData The private keys
     * @return Encrypted text
     * @throws AesEncryptionException if an error occurs during decryption.
     */
    public static String decryptText( String encryptedText, final EncryptedPrivateData privateData )
            throws AesEncryptionException
    {
        final EncryptedPublicData publicData = EncryptedPublicData.fromString( encryptedText );

        // Decrypt source text
        final byte[] decryptedSource = decrypt( publicData, privateData );

        return new String( decryptedSource, CHARSET_ENCODING );
    }

    private static SecretKey getAesSecretKey( byte[] bytes )
    {
        return new SecretKeySpec( bytes, AES_KEY_ALGORITHM );
    }

    private static byte[] getRandomKey( int keySize ) throws AesEncryptionException
    {
        final byte[] randomKey = new byte[keySize];
        try
        {
            final SecureRandom secureRandom = SecureRandom.getInstance( SECURE_RANDOM_ALGORITHM );
            secureRandom.nextBytes( randomKey );
            return randomKey;
        } catch ( NoSuchAlgorithmException ex )
        {
            throw new AesEncryptionException( ex );
        }
    }

    private static void checkSourceHmac( byte[] source,
                                         byte[] expectedHmac,
                                         byte[] hmacKey ) throws AesEncryptionException
    {
        final byte[] observedHmac = getHmac( source, hmacKey );
        if ( !Arrays.equals( expectedHmac, observedHmac ) )
        {
            throw new AesEncryptionException( "Invalid HMAC key" );
        }
    }
}