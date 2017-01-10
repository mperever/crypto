package com.github.mperever.crypto;

public class EncryptedData
{
    private final EncryptedPublicData publicData;
    private final EncryptedPrivateData privateData;

    public EncryptedData( final EncryptedPublicData publicData,
                          final EncryptedPrivateData privateData )
    {
        this.publicData = publicData;
        this.privateData = privateData;
    }

    public EncryptedPublicData getPublicData()
    {
        return this.publicData;
    }

    public EncryptedPrivateData getPrivateData()
    {
        return this.privateData;
    }
}