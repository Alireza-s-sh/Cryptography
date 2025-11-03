using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Documents;

namespace Cryptography
{
    public class CryptoService
    {
        public void EncryptFile(string path, string keyBase64, string alg, string mode)
        {
            byte[] key = Convert.FromBase64String(keyBase64);

            SymmetricAlgorithm algorithm = alg switch
            {
                "AES" => Aes.Create(),
                "DES" => DES.Create(),
                "3DES" => TripleDES.Create(),
                _ => throw new ArgumentException("Unsupported algorithm")
            };

            algorithm.Mode = mode.ToLower() switch
            {
                "cbc" => CipherMode.CBC,
                "ecb" => CipherMode.ECB,
                _ => throw new ArgumentException("Invalid mode")
            };


            // generate a random IV
            algorithm.GenerateIV();

            var outPath = path + ".enc";

            using (FileStream fsInput = new FileStream(path, FileMode.Open, FileAccess.Read))
            using (FileStream fsEncrypted = new FileStream(outPath, FileMode.Create, FileAccess.Write))
            {
                // IV رو اول فایل بنویس تا بعداً برای Decrypt استفاده کنیم
                fsEncrypted.Write(algorithm.IV, 0, algorithm.IV.Length);

                using (var cryptoTransform = algorithm.CreateEncryptor(key, algorithm.IV))
                using (var cryptoStream = new CryptoStream(fsEncrypted, cryptoTransform, CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cryptoStream);
                }
            }
        }

        public void DecryptFile(string path, string keyBase64, string alg, string mode)
        {
            byte[] key = Convert.FromBase64String(keyBase64);

            SymmetricAlgorithm algorithm = alg switch
            {
                "AES" => Aes.Create(),
                "DES" => DES.Create(),
                "3DES" => TripleDES.Create(),
                _ => throw new ArgumentException("Unsupported algorithm")
            };

            algorithm.Mode = mode.ToLower() switch
            {
                "cbc" => CipherMode.CBC,
                "ecb" => CipherMode.ECB,
                _ => throw new ArgumentException("Invalid mode")
            };
            algorithm.Padding = PaddingMode.PKCS7;

            var outPath = path.Replace(".enc", "");

            using (FileStream fsInput = new FileStream(path, FileMode.Open, FileAccess.Read))
            using (FileStream fsDecrypted = new FileStream(outPath, FileMode.Create, FileAccess.Write))
            {
                // IV رو از اول فایل بخون
                byte[] iv = new byte[algorithm.BlockSize / 8];
                fsInput.ReadExactly(iv);

                using (var decryptor = algorithm.CreateDecryptor(key, iv))
                using (var cryptoStream = new CryptoStream(fsInput, decryptor, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(fsDecrypted);
                }
            }
        }


        public string GenerateRandomKey(string algorithm)
        {
            int lengthBytes = algorithm.ToUpper() switch
            {
                "AES" => 32,    // 256-bit
                "DES" => 8,     // 64-bit
                "3DES" => 24,   // 192-bit
                _ => throw new ArgumentException("Unsupported algorithm")
            };

            var data = new byte[lengthBytes];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(data);
            return Convert.ToBase64String(data);
        }

        public string DeriveKeyFromPassword(string password, string algorithm)
        {
            int lengthBytes = algorithm switch
            {
                "AES" => 32,
                "DES" => 8,
                "3DES" => 24,
                _ => throw new ArgumentException("Unsupported algorithm")
            };

            // بهتره هر بار salt جدید بسازی (فعلاً دمو)
            // todo: what is salt, how to generate a generic one?
            var salt = Encoding.UTF8.GetBytes("static-salt-for-demo");
            using var kdf = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            var key = kdf.GetBytes(lengthBytes);
            return Convert.ToBase64String(key);
        }
    }
}
