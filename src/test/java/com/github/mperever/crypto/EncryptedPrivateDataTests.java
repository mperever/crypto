package com.github.mperever.crypto;

import org.junit.Assert;
import org.junit.Test;

/**
 * Represents unit tests for {@link EncryptedPrivateData} class.
 *
 * @author mperever
 *
 */
public class EncryptedPrivateDataTests
{
    @Test
    public void saveAndFrom_test()
    {
        final byte[] aesKey = new byte[] {1,2,3};
        final byte[] hmacKey = new byte[] {'a','b'};
        // Save
        final EncryptedPrivateData expectedData = new EncryptedPrivateData( aesKey, hmacKey );
        final String encryptedText = expectedData.saveToString();

        // From
        final EncryptedPrivateData actualData = EncryptedPrivateData.fromString( encryptedText, aesKey.length );

        Assert.assertArrayEquals( "AES keys do not equal", aesKey, actualData.getAesKey() );
        Assert.assertArrayEquals( "HMAC keys do not equal", hmacKey, actualData.getHmacKey() );
    }
}