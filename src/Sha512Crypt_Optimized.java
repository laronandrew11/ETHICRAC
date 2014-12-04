/*
   Sha512Crypt.java

   Created: 18 December 2007

   Java Port By: James Ratcliff, falazar@arlut.utexas.edu

   This class implements the new generation, scalable, SHA512-based
   Unix 'crypt' algorithm developed by a group of engineers from Red
   Hat, Sun, IBM, and HP for common use in the Unix and Linux
   /etc/shadow files.

   The Linux glibc library (starting at version 2.7) includes support
   for validating passwords hashed using this algorithm.

   The algorithm itself was released into the Public Domain by Ulrich
   Drepper <drepper@redhat.com>.  A discussion of the rationale and
   development of this algorithm is at

   http://people.redhat.com/drepper/sha-crypt.html

   and the specification and a sample C language implementation is at

   http://people.redhat.com/drepper/SHA-crypt.txt

   This Java Port is

     Copyright (c) 2008-2013 The University of Texas at Austin.

     All rights reserved.

     Redistribution and use in source and binary form are permitted
     provided that distributions retain this entire copyright notice
     and comment. Neither the name of the University nor the names of
     its contributors may be used to endorse or promote products
     derived from this software without specific prior written
     permission. THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY
     EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
     IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
     PARTICULAR PURPOSE.

*/


import java.security.MessageDigest;

/*------------------------------------------------------------------------------
                                                                           class
                                                                     Sha512Crypt

------------------------------------------------------------------------------*/

/**
 * <p>This class defines a method, {@link
 * Sha512Crypt#Sha512_crypt(java.lang.String, java.lang.String, int)
 * Sha512_crypt()}, which takes a password and a salt string and
 * generates a Sha512 encrypted password entry.</p>
 *
 * <p>This class implements the new generation, scalable, SHA512-based
 * Unix 'crypt' algorithm developed by a group of engineers from Red
 * Hat, Sun, IBM, and HP for common use in the Unix and Linux
 * /etc/shadow files.</p>
 *
 * <p>The Linux glibc library (starting at version 2.7) includes
 * support for validating passwords hashed using this algorithm.</p>
 *
 * <p>The algorithm itself was released into the Public Domain by
 * Ulrich Drepper &lt;drepper@redhat.com&gt;.  A discussion of the
 * rationale and development of this algorithm is at</p>
 *
 * <p>http://people.redhat.com/drepper/sha-crypt.html</p>
 *
 * <p>and the specification and a sample C language implementation is
 * at</p>
 *
 * <p>http://people.redhat.com/drepper/SHA-crypt.txt</p>
 */

public final class Sha512Crypt_Optimized
{
  static private final String sha512_salt_prefix = "$6$";
  static private final String sha512_rounds_prefix = "rounds=";
  static private final int SALT_LEN_MAX = 16;
  static private final int ROUNDS_DEFAULT = 5000;
  static private final int ROUNDS_MIN = 1000;
  static private final int ROUNDS_MAX = 999999999;
  static private final String SALTCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  static private final String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  static private MessageDigest getSHA512()
  {
    try
      {
        return MessageDigest.getInstance("SHA-512");
      }
    catch (java.security.NoSuchAlgorithmException ex)
      {
        throw new RuntimeException(ex);
      }
  }

  /**
   * <p>This method actually generates an Sha512 crypted password hash
   * from a plaintext password and a salt.</p>
   *
   * <p>The resulting string will be in the form
   * '$6$&lt;rounds=n&gt;$&lt;salt&gt;$&lt;hashed mess&gt;</p>
   *
   * @param keyStr Plaintext password
   *
   * @param saltStr An encoded salt/roundes which will be consulted to determine the salt
   * and round count, if not null
   *
   * @param roundsCount If this value is not 0, this many rounds will
   * used to generate the hash text.
   *
   * @return The Sha512 Unix Crypt hash text for the keyStr
   */

  public static final boolean Sha512_crypt(String keyStr, String saltStr, int roundsCount, String hash)
  {
    MessageDigest ctx = getSHA512();
    MessageDigest alt_ctx = getSHA512();

    byte[] alt_result;
    byte[] temp_result;
    byte[] p_bytes = null;
    byte[] s_bytes = null;
    int cnt, cnt2;
    int rounds = ROUNDS_DEFAULT; // Default number of rounds.
    StringBuilder buffer;
    boolean include_round_count = false;

    /* -- */

    if (saltStr != null)
      {
        if (saltStr.startsWith(sha512_salt_prefix))
          {
            saltStr = saltStr.substring(sha512_salt_prefix.length());
          }

        if (saltStr.startsWith(sha512_rounds_prefix))
          {
            String num = saltStr.substring(sha512_rounds_prefix.length(), saltStr.indexOf('$'));
            int srounds = Integer.valueOf(num).intValue();
            saltStr = saltStr.substring(saltStr.indexOf('$')+1);
            rounds = Math.max(ROUNDS_MIN, Math.min(srounds, ROUNDS_MAX));
            include_round_count = true;
          }

        if (saltStr.length() > SALT_LEN_MAX)
          {
            saltStr = saltStr.substring(0, SALT_LEN_MAX);
          }

        // gnu libc's crypt(3) implementation allows the salt to end
        // in $ which is then ignored.

        if (saltStr.endsWith("$"))
          {
            saltStr = saltStr.substring(0, saltStr.length() - 1);
          }
        else
          {
            if (saltStr.indexOf("$") != -1)
              {
                saltStr = saltStr.substring(0, saltStr.indexOf("$"));
              }
          }
      }
    else
      {
        java.util.Random randgen = new java.util.Random();
        StringBuilder saltBuf = new StringBuilder();

        while (saltBuf.length() < 16)
          {
            int index = (int) (randgen.nextFloat() * SALTCHARS.length());
            saltBuf.append(SALTCHARS.substring(index, index+1));
          }

        saltStr = saltBuf.toString();
      }

    if (roundsCount != 0)
      {
        rounds = Math.max(ROUNDS_MIN, Math.min(roundsCount, ROUNDS_MAX));
      }

    byte[] key = keyStr.getBytes();
    byte[] salt = saltStr.getBytes();

    ctx.reset();
    ctx.update(key, 0, key.length);
    ctx.update(salt, 0, salt.length);

    alt_ctx.reset();
    alt_ctx.update(key, 0, key.length);
    alt_ctx.update(salt, 0, salt.length);
    alt_ctx.update(key, 0, key.length);

    alt_result = alt_ctx.digest();

    for (cnt = key.length; cnt > 64; cnt -= 64)
      {
        ctx.update(alt_result, 0, 64);
      }

    ctx.update(alt_result, 0, cnt);

    for (cnt = key.length; cnt > 0; cnt >>= 1)
      {
        if ((cnt & 1) != 0)
          {
            ctx.update(alt_result, 0, 64);
          }
        else
          {
            ctx.update(key, 0, key.length);
          }
      }

    alt_result = ctx.digest();

    alt_ctx.reset();

    for (cnt = 0; cnt < key.length; ++cnt)
      {
        alt_ctx.update(key, 0, key.length);
      }

    temp_result = alt_ctx.digest();

    p_bytes = new byte[key.length];

    for (cnt2 = 0, cnt = p_bytes.length; cnt >= 64; cnt -= 64)
      {
        System.arraycopy(temp_result, 0, p_bytes, cnt2, 64);
        cnt2 += 64;
      }

    System.arraycopy(temp_result, 0, p_bytes, cnt2, cnt);

    alt_ctx.reset();

    for (cnt = 0; cnt < 16 + (alt_result[0]&0xFF); ++cnt)
      {
        alt_ctx.update(salt, 0, salt.length);
      }

    temp_result = alt_ctx.digest();

    s_bytes = new byte[salt.length];

    for (cnt2 = 0, cnt = s_bytes.length; cnt >= 64; cnt -= 64)
      {
        System.arraycopy(temp_result, 0, s_bytes, cnt2, 64);
        cnt2 += 64;
      }

    System.arraycopy(temp_result, 0, s_bytes, cnt2, cnt);

    /* Repeatedly run the collected hash value through SHA512 to burn
       CPU cycles.  */

    for (cnt = 0; cnt < rounds; ++cnt)
      {
        ctx.reset();

        if ((cnt & 1) != 0)
          {
            ctx.update(p_bytes, 0, key.length);
          }
        else
          {
            ctx.update (alt_result, 0, 64);
          }

        if (cnt % 3 != 0)
          {
            ctx.update(s_bytes, 0, salt.length);
          }

        if (cnt % 7 != 0)
          {
            ctx.update(p_bytes, 0, key.length);
          }

        if ((cnt & 1) != 0)
          {
            ctx.update(alt_result, 0, 64);
          }
        else
          {
            ctx.update(p_bytes, 0, key.length);
          }

        alt_result = ctx.digest();
      }

    for (int i = 0; i < 7; i ++) {
    	int a = 3*i, b = 3*i + 21, c = 3*i + 42;
    	
    	if(!compare_b64_from_24bit(alt_result[a],alt_result[b],alt_result[c],4,hash.substring(12*i,12*i+4)))
    		return false;
    	if (!compare_b64_from_24bit(alt_result[b+1],alt_result[c+1],alt_result[a+1],4,hash.substring(12*i+4,12*i+8)))
    		return false;
    	if (!compare_b64_from_24bit(alt_result[c+2],alt_result[a+2],alt_result[b+2],4,hash.substring(12*i+8,12*i+12)))
    		return false;
    }
    
    /* Clear the buffer for the intermediate result so that people
    attaching to processes or reading core dumps cannot get any
    information. */

    ctx.reset();
    
    return compare_b64_from_24bit ((byte)0x00, (byte)0x00, alt_result[63], 2, hash.substring(hash.length()-2));
  }

  private static final boolean compare_b64_from_24bit(byte B2, byte B1, byte B0, int size, String hash)
  {
    int v = ((((int) B2) & 0xFF) << 16) | ((((int) B1) & 0xFF) << 8) | ((int)B0 & 0xff);

    StringBuilder result = new StringBuilder();

    while (--size >= 0)
      {
        result.append(itoa64.charAt((int) (v & 0x3f)));
        v >>>= 6;
      }  
    
    return result.toString().compareTo(hash) == 0;
  }
  
  
  private static final String b64_from_24bit(byte B2, byte B1, byte B0, int size)
  {
    int v = ((((int) B2) & 0xFF) << 16) | ((((int) B1) & 0xFF) << 8) | ((int)B0 & 0xff);

    StringBuilder result = new StringBuilder();

    while (--size >= 0)
      {
        result.append(itoa64.charAt((int) (v & 0x3f)));
        v >>>= 6;
      }
    
    return result.toString();
  }
}