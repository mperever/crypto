package com.github.mperever.crypto;

import com.github.mperever.utils.ArraysUtils;

import java.util.Arrays;
import java.util.Base64;

/**
 * Represents class to keep encrypted public data.
 *
 * @author mperever
 *
 */
public class EncryptedPublicData
{
    private static final int DEFAULT_INIT_VECTOR_SIZE = 16; // in bytes
    private static final int DEFAULT_HMAC_SIZE = 32; // in bytes

    private final byte[] encryptedData;
    private final byte[] initVector;
    private final byte[] hmac;

    /**
     * Constructor with public information of encryption.
     *
     * @param encryptedData The encrypted data
     * @param initVector The initialization vector for encryption
     * @param hmac HMAC of encrypted data
     */
    public EncryptedPublicData( byte[] encryptedData, byte[] initVector, byte[] hmac )
    {
        this.encryptedData = encryptedData.clone();
        this.initVector = initVector.clone();
        this.hmac = hmac.clone();
    }

    /**
     * Parse source string to create instance of {@link EncryptedPublicData}.
     * Default size for initialization vector and HMAC will be used.
     *
     * @param source The parsable source string
     * @return The instance of {@link EncryptedPublicData}.
     */
    public static EncryptedPublicData fromString( String source )
    {
        return fromString( source, DEFAULT_INIT_VECTOR_SIZE, DEFAULT_HMAC_SIZE );
    }

    /**
     * Parse source string to create instance of {@link EncryptedPublicData},
     * using custom sizes of initialization vector and HMAC.
     *
     * @param source The parsable source string
     * @param initVectorSize The initialization vector size in bytes
     * @param hmacSize The HMAC size in bytes
     * @return The instance of {@link EncryptedPublicData}.
     */
    public static EncryptedPublicData fromString( String source, int initVectorSize, int hmacSize )
    {
        // Convert source base64 string to bytes
        final byte[] dataToSplit = Base64.getDecoder().decode( source );

        // Split data into encrypted data, HMAC and init vector
        final int encryptedDataSize = dataToSplit.length - ( hmacSize + initVectorSize );
        final byte[] encryptedData = Arrays.copyOf( dataToSplit, encryptedDataSize );

        final byte[] hmac = new byte[hmacSize];
        System.arraycopy( dataToSplit, encryptedDataSize, hmac, 0, hmacSize );

        final byte[] initVector = new byte[initVectorSize];
        System.arraycopy( dataToSplit,
                encryptedDataSize + hmacSize,
                initVector,
                0,
                initVectorSize );

        return new EncryptedPublicData( encryptedData, initVector, hmac );
    }

    /**
     * Gets encrypted data.
     *
     * @return The encrypted data
     */
    public byte[] getEncryptedData()
    {
        return this.encryptedData.clone();
    }

    /**
     * Gets initialization vector.
     *
     * @return The initialization vector
     */
    public byte[] getInitVector()
    {
        return this.initVector.clone();
    }

    /**
     * Gets the HMAC.
     *
     * @return The HMAC
     */
    public byte[] getHmac()
    {
        return this.hmac.clone();
    }

    /**
     * Save current instance to string.
     *
     * @return The string that represents current object
     */
    public String saveToString()
    {
        final byte[] dataToSave =
                ArraysUtils.concatAll( this.encryptedData, this.hmac, this.initVector );

        return Base64.getEncoder().encodeToString( dataToSave );
    }
}