package com.github.mperever.utils;

import java.util.Arrays;

public class ArraysUtils
{
    private ArraysUtils()
    {
    }

    /**
     * Concat two arrays of bytes into one.
     *
     * @param first The first array for concatenation.
     * @param second The second array for concatenation.
     * @return The combination of first and second arrays.
     */
    public static byte[] concat( byte[] first, byte[] second )
    {
        final int firstSize = first.length;
        final int secondSize = second.length;
        final byte[] result = new byte[firstSize + secondSize];

        System.arraycopy( first, 0, result, 0, firstSize );
        System.arraycopy( second, 0, result, firstSize, secondSize );

        return result;
    }

    /**
     * Concat several arrays of bytes into one.
     *
     * @param first The first array for concatenation.
     * @param rest The rest of arrays for concatenation.
     * @return The combination of arrays.
     */
    public static byte[] concatAll( byte[] first, byte[]... rest )
    {
        int totalLength = first.length;
        for ( byte[] array : rest )
        {
            totalLength += array.length;
        }

        final byte[] result = Arrays.copyOf( first, totalLength );
        int offset = first.length;
        for ( byte[] array : rest )
        {
            System.arraycopy( array, 0, result, offset, array.length );
            offset += array.length;
        }
        return result;
    }
}