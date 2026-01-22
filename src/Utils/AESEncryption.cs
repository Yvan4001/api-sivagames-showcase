/*
 * SIVACORE ENGINE - SECURITY MODULE SAMPLE
 * ----------------------------------------
 * This file is a stripped-down version of the encryption logic used in production.
 * It demonstrates:
 * 1. AES-256 Implementation (CBC Mode with PKCS7 Padding).
 * 2. Secure IV handling (Randomized per transaction).
 * 3. Dependency Injection integration with Legacy Static fallback.
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using api_sivagames.Interfaces;

namespace api_sivagames.Utils;

public class AESEncryption : IAesEncryption
{
    private readonly byte[] _aesKey;
    private static IAesEncryption _staticInstance;

    // AES Block size / IV size (128 bits = 16 bytes)
    private const int AesBlockSize = 16;

    public AESEncryption(IConfiguration config) 
    {
        // Security: Key is loaded from Environment/Vault, never hardcoded.
        var keyStr = config["AES_KEY"] ?? Environment.GetEnvironmentVariable("AES_KEY");
        
        if (string.IsNullOrWhiteSpace(keyStr))
            throw new InvalidOperationException("CRITICAL: AES_KEY is missing from configuration.");
        
        _aesKey = ParseKey(keyStr);
        
        // Keep a static reference for legacy static call sites (pragmatic approach for existing entities)
        _staticInstance = this;
    }

    private byte[] ParseKey(string value)
    {
        // Support for explicit prefixes (base64: / hex:)
        if (value.StartsWith("base64:", StringComparison.OrdinalIgnoreCase))
            return ValidateKeyLength(Convert.FromBase64String(value[7..]));
        if (value.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
            return ValidateKeyLength(ConvertHexStringToByteArray(value[4..]));

        // Autodetect format
        if (value.Contains('=') || value.Contains('+') || value.Contains('/'))
        {
            try { return ValidateKeyLength(Convert.FromBase64String(value)); }
            catch { /* fall back to hex */ }
        }

        return ValidateKeyLength(ConvertHexStringToByteArray(value));
    }

    private byte[] ValidateKeyLength(byte[] bytes)
    {
        // Ensure Key is 128, 192, or 256 bits
        if (bytes.Length != 16 && bytes.Length != 24 && bytes.Length != 32)
            throw new InvalidOperationException("AES_KEY must be 16, 24, or 32 bytes.");

        return bytes;
    }

    private byte[] ConvertHexStringToByteArray(string hexString)
    {
        if (string.IsNullOrWhiteSpace(hexString) || (hexString.Length % 2) != 0)
            throw new ArgumentException("Hex string must have an even number of characters.");

        var bytes = new byte[hexString.Length / 2];
        for (int i = 0; i < hexString.Length; i += 2)
        {
            var byteValue = hexString.Substring(i, 2);
            bytes[i / 2] = Convert.ToByte(byteValue, 16);
        }
        return bytes;
    }

    public string Encrypt(string plainText)
    {
        if (_aesKey == null)
            throw new InvalidOperationException("AESEncryption is not initialized.");

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        // SECURITY CRITICAL: Always generate a new random IV for every encryption.
        // Never reuse an IV with the same key.
        aes.GenerateIV();
        byte[] iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(_aesKey, iv);
        using var ms = new MemoryStream();

        // 1. Prepend the IV (unencrypted) to the stream so it can be retrieved for decryption
        ms.Write(iv, 0, iv.Length);

        // 2. Write the encrypted data
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs, Encoding.UTF8))
        {
            sw.Write(plainText);
        }

        // 3. Return combined [IV + CipherText] as Base64
        return Convert.ToBase64String(ms.ToArray());
    }

    public string Decrypt(string cipherTextWithIvBase64)
    {
        if (_aesKey == null)
            throw new InvalidOperationException("AESEncryption is not initialized.");

        byte[] dataWithIv;
        try
        {
            dataWithIv = Convert.FromBase64String(cipherTextWithIvBase64);
        }
        catch (FormatException)
        {
            // Fail-safe: return raw text if not base64 (migration support)
            return cipherTextWithIvBase64;
        }

        if (dataWithIv.Length <= AesBlockSize)
            throw new CryptographicException("Invalid cipher text length.");

        // 1. Extract the IV (first 16 bytes)
        byte[] iv = new byte[AesBlockSize];
        Buffer.BlockCopy(dataWithIv, 0, iv, 0, AesBlockSize);

        // 2. Extract the actual CipherText
        byte[] cipherText = new byte[dataWithIv.Length - AesBlockSize];
        Buffer.BlockCopy(dataWithIv, AesBlockSize, cipherText, 0, cipherText.Length);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        // 3. Decrypt using the Key and the extracted IV
        using var decryptor = aes.CreateDecryptor(_aesKey, iv);

        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs, Encoding.UTF8);
        try
        {
            return sr.ReadToEnd();
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Decryption failed. Integrity check failed or key mismatch.", ex);
        }
    }

    // --- Legacy Static Proxies (Bridge Pattern) ---
    public static string EncryptStatic(string plainText)
    {
        return _staticInstance != null 
            ? _staticInstance.Encrypt(plainText) 
            : throw new InvalidOperationException("AESEncryption DI container not ready.");
    }

    public static string DecryptStatic(string cipherTextWithIvBase64)
    {
        return _staticInstance != null 
            ? _staticInstance.Decrypt(cipherTextWithIvBase64) 
            : throw new InvalidOperationException("AESEncryption DI container not ready.");
    }
}