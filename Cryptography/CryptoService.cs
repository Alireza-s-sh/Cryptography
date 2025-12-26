using Cryptography.Enums;
using Cryptography.Models;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace Cryptography
{
    public class CryptoService
    {
        public void EncryptFile(
        string path,
        string keyBase64,
        string alg,
        string mode,
        string consumerPublicKeyBase64,
        string producerPrivateKeyBase64,
        EncryptionMethod encryptionMethod)
        {
            byte[] symmetricKey = Convert.FromBase64String(keyBase64);
            byte[] fileBytes = File.ReadAllBytes(path);

            // 🔹 Step A: Integrity & Authentication
            var securePackage = BuildIntegrityPackage(
                fileBytes,
                symmetricKey,
                producerPrivateKeyBase64);

            if (encryptionMethod == EncryptionMethod.RSADirect)
            {
                var rsaEncryptedBlock = EncryptPackageWithRsaDirect(
                    securePackage,
                    consumerPublicKeyBase64);

                File.WriteAllBytes(path + ".enc", rsaEncryptedBlock);
                return;
            }

            // serialize package
            byte[] packageBytes = JsonSerializer.SerializeToUtf8Bytes(securePackage);
            byte[] encryptedSymmetricKey = default;

            if (encryptionMethod is EncryptionMethod.SecureEnvelope)
            {

                // 🔹 Encrypt symmetric key with consumer public key
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPublicKey(
                        Convert.FromBase64String(consumerPublicKeyBase64),
                        out _);

                    encryptedSymmetricKey = rsa.Encrypt(
                        symmetricKey,
                        RSAEncryptionPadding.OaepSHA256);
                }
            }

            // 🔹 Symmetric encryption (همون روش قبلی)
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

            algorithm.GenerateIV();

            var outPath = path + ".enc";

            using var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write);
            using var bw = new BinaryWriter(fs);

            if (encryptionMethod is EncryptionMethod.SecureEnvelope)
            {
                // 🔹 Write encrypted symmetric key
                bw.Write(value: encryptedSymmetricKey.Length);
                bw.Write(encryptedSymmetricKey);
            }

            // 🔹 Write IV
            bw.Write(algorithm.IV.Length);
            bw.Write(algorithm.IV);

            // 🔹 Encrypt package
            using var encryptor = algorithm.CreateEncryptor(symmetricKey, algorithm.IV);
            using var cryptoStream = new CryptoStream(fs, encryptor, CryptoStreamMode.Write);

            cryptoStream.Write(packageBytes, 0, packageBytes.Length);
        }
        public byte[] EncryptPackageWithRsaDirect(
        SecurePackage package,
        string consumerPublicKeyBase64)
        {
            // 1. serialize package
            byte[] packageBytes = JsonSerializer.SerializeToUtf8Bytes(package);

            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(
                Convert.FromBase64String(consumerPublicKeyBase64),
                out _);

            // 2. RSA size check (خیلی مهم)
            int maxDataSize =
                (rsa.KeySize / 8) - 2 * 32 - 2;

            if (packageBytes.Length > maxDataSize)
            {
                throw new CryptographicException(
                    $"Package too large for RSA direct encryption. Size={packageBytes.Length}, Max={maxDataSize}");
            }

            // 3. Encrypt directly with RSA
            return rsa.Encrypt(
                packageBytes,
                RSAEncryptionPadding.OaepSHA256);
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

            var outPath = path.Replace(".enc", "");

            using (FileStream fsInput = new FileStream(path, FileMode.Open, FileAccess.Read))
            using (FileStream fsDecrypted = new FileStream(outPath, FileMode.Create, FileAccess.Write))
            {
                // read IV from beginning of file
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

            var rng = RandomNumberGenerator.Create();
            var salt = new byte[16];
            rng.GetBytes(salt);
            using var kdf = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            var key = kdf.GetBytes(lengthBytes);
            return Convert.ToBase64String(key);
        }
        public SecurePackage BuildIntegrityPackage(
        byte[] data,
        byte[] macKey,
        string producerPrivateKeyBase64)
        {
            // 1. MAC
            byte[] mac;
            using (var hmac = new HMACSHA256(macKey))
            {
                mac = hmac.ComputeHash(data);
            }

            // 2. Sign(Data + MAC)
            byte[] signedBytes;
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(
                    Convert.FromBase64String(producerPrivateKeyBase64),
                    out _);

                var toSign = data.Concat(mac).ToArray();

                signedBytes = rsa.SignData(
                    toSign,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }

            return new SecurePackage
            {
                Data = data,
                Mac = mac,
                Signature = signedBytes
            };
        }

    }

    public class KeyManager
    {
        

        public KeyModel LoadOrCreateKeys(string FileName)
        {
            if (File.Exists(FileName))
            {
                var json = File.ReadAllText(FileName);
                return JsonSerializer.Deserialize<KeyModel>(json)!;
            }

            using var rsa = RSA.Create(2048);

            var model = new KeyModel
            {
                PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey()),
                PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey()),
                CreatedAt = DateTime.UtcNow
            };

            var output = JsonSerializer.Serialize(model, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(FileName, output);

            return model;
        }
    }

}
