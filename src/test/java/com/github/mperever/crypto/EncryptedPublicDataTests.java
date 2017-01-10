package com.github.mperever.crypto;

import org.junit.Assert;
import org.junit.Test;

/**
 * Represents unit tests for {@link EncryptedPublicData} class.
 *
 * @author mperever
 *
 */
public class EncryptedPublicDataTests
{
    @Test
    public void saveAndFrom_test()
    {
        final byte[] encryptedData = new byte[] {1,2,3};
        final byte[] initVector = new byte[] {4,5};
        final byte[] hmac = new byte[] {'a','b'};

        // Save
        final EncryptedPublicData expectedData =
                new EncryptedPublicData( encryptedData, initVector, hmac );
        final String encryptedText = expectedData.saveToString();

        // From
        final EncryptedPublicData actualData =
                EncryptedPublicData.fromString( encryptedText, initVector.length, hmac.length );

        Assert.assertArrayEquals( "Encrypted data does not equal", encryptedData, actualData.getEncryptedData() );
        Assert.assertArrayEquals( "Init vectors do not equal", initVector, actualData.getInitVector() );
        Assert.assertArrayEquals( "HMACs do not equal", hmac, actualData.getHmac() );
    }
}