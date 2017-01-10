package com.github.mperever.crypto;

public class AesEncryptionException extends Exception
{
    public AesEncryptionException( String message )
    {
        super( message );
    }

    public AesEncryptionException( String message, Throwable exception )
    {
        super( message, exception );
    }

    public AesEncryptionException( Throwable exception )
    {
        super( exception );
    }
}