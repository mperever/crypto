package com.github.mperever.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

/**
 * Represents unit tests for {@link AesEncryptionUtilsTests} class.
 *
 * @author mperever
 *
 */
public class AesEncryptionUtilsTests
{
    private static final String TEXT = "Hello World!";
    private static final int AES_KEY_SIZE = 32;
    private static final int INIT_VECTOR_SIZE = 16;
    private static final int HMAC_KEY_SIZE = 32;
    private static final EncryptedPrivateData PRIVATE_DATA =
            new EncryptedPrivateData(new byte[AES_KEY_SIZE], new byte[HMAC_KEY_SIZE]);

    @Test
    public void getAesKey_test() throws AesEncryptionException
    {
        final byte[] aesFirst = AesEncryptionUtils.getAesKey();
        Assert.assertNotNull( "AES key is null", aesFirst );
        Assert.assertEquals( "AES key length is wrong", AES_KEY_SIZE, aesFirst.length );

        // AES is random
        final byte[] aesSecond = AesEncryptionUtils.getAesKey();
        Assert.assertNotEquals( "AES keys are the same",
                Arrays.toString( aesFirst ),
                Arrays.toString( aesSecond ) );
    }

    @Test
    public void getIv_test() throws AesEncryptionException
    {
        final byte[] ivFirst = AesEncryptionUtils.getIv();
        Assert.assertNotNull( "Init vector is null", ivFirst );
        Assert.assertEquals( "Init vector length is wrong", INIT_VECTOR_SIZE, ivFirst.length );

        // Init vector is random
        final byte[] ivSecond = AesEncryptionUtils.getIv();
        Assert.assertNotEquals( "Init vectors are the same",
                Arrays.toString( ivFirst ),
                Arrays.toString( ivSecond ) );
    }

    @Test
    public void encryptAndDecryptText_test() throws AesEncryptionException
    {
        // Encrypt text
        final EncryptedData encryptedData = AesEncryptionUtils.encryptText( TEXT );
        Assert.assertNotEquals( "Encrypted data are the same",
                TEXT,
                new String(encryptedData.getPublicData().getEncryptedData(), StandardCharsets.UTF_8 ) );
        final String encryptedText = encryptedData.getPublicData().saveToString();

        // Decrypt text
        final String actualDecryptedText =
                AesEncryptionUtils.decryptText( encryptedText, encryptedData.getPrivateData() );
        Assert.assertEquals( "Decrypted text is wrong", TEXT, actualDecryptedText );
    }

    @Test
    public void encryptAndDecryptTextWithPrivateData_test() throws AesEncryptionException
    {
        // Encrypt text
        final EncryptedPublicData publicData =
                AesEncryptionUtils.encryptText( TEXT, PRIVATE_DATA );
        final String encryptedText = publicData.saveToString();

        // Decrypt text
        final String actualDecryptedText =
                AesEncryptionUtils.decryptText( encryptedText, PRIVATE_DATA );
        Assert.assertEquals( "Decrypted text is wrong", TEXT, actualDecryptedText );
    }

    @Test
    public void encryptAndDecryptBytes_test() throws AesEncryptionException
    {
        // Encrypt
        final byte[] source = new byte[] {1,2,3};
        final EncryptedPublicData publicData =
                AesEncryptionUtils.encrypt( source, new byte[INIT_VECTOR_SIZE], PRIVATE_DATA );
        Assert.assertNotEquals( "Encrypted bytes are the same",
                Arrays.toString( source ),
                Arrays.toString( publicData.getEncryptedData() ) );

        // Decrypt
        final byte[] decryptSource = AesEncryptionUtils.decrypt( publicData, PRIVATE_DATA );
        Assert.assertArrayEquals( "Decrypted bytes are wrong", source, decryptSource );
    }
}