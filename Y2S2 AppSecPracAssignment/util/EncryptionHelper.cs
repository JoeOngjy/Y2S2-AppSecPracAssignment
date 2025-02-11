using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class EncryptionHelper
{
    private readonly byte[] _encryptionKey = Encoding.UTF8.GetBytes("4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D");

    public string Encrypt(string text)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = _encryptionKey;
            aesAlg.GenerateIV();
            var iv = aesAlg.IV;

            using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv))
            using (var ms = new MemoryStream())
            {
                ms.Write(iv, 0, iv.Length);
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var writer = new StreamWriter(cs))
                {
                    writer.Write(text);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    public string Decrypt(string encryptedText)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = _encryptionKey;

            // Convert the base64 string to a byte array
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

            // Extract the IV from the beginning of the encrypted data
            byte[] iv = new byte[aesAlg.BlockSize / 8];
            Array.Copy(encryptedBytes, 0, iv, 0, iv.Length);

            // Extract the encrypted text from the byte array
            byte[] encryptedData = new byte[encryptedBytes.Length - iv.Length];
            Array.Copy(encryptedBytes, iv.Length, encryptedData, 0, encryptedData.Length);

            // Decrypt the data
            aesAlg.IV = iv;
            using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            using (var ms = new MemoryStream(encryptedData))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cs))
            {
                return reader.ReadToEnd();
            }
        }
    }
}

