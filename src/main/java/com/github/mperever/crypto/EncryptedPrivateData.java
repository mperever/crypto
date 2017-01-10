package com.github.mperever.crypto;

import com.github.mperever.utils.ArraysUtils;

import java.util.Base64;

/**
 * Represents class to keep encrypted private data.
 *
 * @author mperever
 *
 */
public class EncryptedPrivateData
{
    private static final int DEFAULT_AES_KEY_SIZE = 32; // in bytes

    private final byte[] aesKey;
    private final byte[] hmacKey;

    public EncryptedPrivateData( byte[] aesKey, byte[] hmacKey )
    {
        this.aesKey = aesKey.clone();
        this.hmacKey = hmacKey.clone();
    }

    public static EncryptedPrivateData fromString( String source )
    {
        return fromString( source, DEFAULT_AES_KEY_SIZE );
    }

    /**
     * Parse source string to create instance of {@link EncryptedPrivateData}.
     *
     * @param source The parsable source string
     * @param aesKeySize The bytes size for AES256 private key.
     * @return The instance of {@link EncryptedPrivateData}.
     */
    public static EncryptedPrivateData fromString( String source, int aesKeySize )
    {
        // Convert source base64 string to bytes
        final byte[] dataToSplit = Base64.getDecoder().decode( source );

        // Split data into AES Key and HMAC Key
        final byte[] aesKey = new byte[aesKeySize];
        System.arraycopy( dataToSplit, 0, aesKey, 0, aesKeySize );

        final int hmacKeySize = dataToSplit.length - aesKeySize;
        final byte[] hmacKey = new byte[hmacKeySize];
        System.arraycopy( dataToSplit, aesKeySize, hmacKey, 0, hmacKeySize );

        return new EncryptedPrivateData( aesKey, hmacKey );
    }

    public byte[] getAesKey()
    {
        return this.aesKey.clone();
    }

    public byte[] getHmacKey()
    {
        return this.hmacKey.clone();
    }

    /**
     * Save current instance to string.
     *
     * @return The string that represents current object
     */
    public String saveToString()
    {
        final byte[] dataToSave = ArraysUtils.concat( this.aesKey, this.hmacKey );
        return Base64.getEncoder().encodeToString( dataToSave );
    }
}