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

            // 🔹Making Header
            var header = new EncryptionHeader
            {
                Version = 1,
                Method = encryptionMethod
            };
            byte[] headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);

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

                using var fileStream = new FileStream(path + ".enc", FileMode.Create, FileAccess.Write);
                using var binaryWriter = new BinaryWriter(fileStream);

                // 🔹 Header
                binaryWriter.Write(headerBytes.Length);
                binaryWriter.Write(headerBytes);

                // 🔹 RSA Block
                binaryWriter.Write(rsaEncryptedBlock.Length);
                binaryWriter.Write(rsaEncryptedBlock);

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

            // 🔹 Header
            bw.Write(headerBytes.Length);
            bw.Write(headerBytes);

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

        #region Decryption

        // =========================
        // 🔐 PUBLIC ENTRY POINT
        // =========================
        public void DecryptFile(
            string path,
            string alg,
            string mode,
            string consumerPrivateKeyBase64,
            string producerPublicKeyBase64,
            string symmetricKeyBase64)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            using var br = new BinaryReader(fs);

            // 🔹 Step 1: Read Header
            var header = ReadEncryptionHeader(br);

            byte[] decryptedPackageBytes = header.Method switch
            {
                EncryptionMethod.SecureEnvelope =>
                    DecryptSecureEnvelope(br, consumerPrivateKeyBase64, alg, mode),

                EncryptionMethod.SymmetricEncryption =>
                    DecryptSymmetric(br, symmetricKeyBase64
                        ?? throw new CryptographicException("Symmetric key is required"), alg, mode),

                EncryptionMethod.RSADirect =>
                    DecryptRsaDirect(br, consumerPrivateKeyBase64),

                _ => throw new CryptographicException("Unknown encryption method")
            };

            // 🔹 Step 2: Extract Package
            var package = DeserializeSecurePackage(decryptedPackageBytes);

            // 🔹 Step 3: Verification
            VerifySignatureOrThrow(package, producerPublicKeyBase64);
            VerifyMacOrThrow(package, symmetricKeyBase64);

            // 🔹 Step 4: Save File
            SaveDecryptedFile(path, package.Data);
        }

        // =========================
        // 📦 HEADER
        // =========================
        private EncryptionHeader ReadEncryptionHeader(BinaryReader br)
        {
            int len = br.ReadInt32();
            var bytes = br.ReadBytes(len);

            return JsonSerializer.Deserialize<EncryptionHeader>(bytes)
                   ?? throw new CryptographicException("Invalid header");
        }

        // =========================
        // 🔑 SECURE ENVELOPE
        // =========================
        private byte[] DecryptSecureEnvelope(
        BinaryReader br,
        string myPrivateKeyBase64,
        string alg,
        string mode)
        {
            int keyLen = br.ReadInt32();
            byte[] encryptedKey = br.ReadBytes(keyLen);

            byte[] symmetricKey = DecryptSymmetricKey(encryptedKey, myPrivateKeyBase64);

            int ivLen = br.ReadInt32();
            byte[] iv = br.ReadBytes(ivLen);

            return DecryptSymmetricPayload(br, symmetricKey, iv, alg, mode);
        }


        private byte[] DecryptSymmetricKey(byte[] encryptedKey, string privateKeyBase64)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(
                Convert.FromBase64String(privateKeyBase64),
                out _);
            try
            {
                return rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }   
        }

        // =========================
        // 🔐 SYMMETRIC (KEY INPUT)
        // =========================
        private byte[] DecryptSymmetric(
        BinaryReader br,
        string symmetricKeyBase64,
        string alg,
        string mode)
        {
            byte[] key = Convert.FromBase64String(symmetricKeyBase64);

            int ivLen = br.ReadInt32();
            byte[] iv = br.ReadBytes(ivLen);

            return DecryptSymmetricPayload(br, key, iv, alg, mode);
        }


        // =========================
        // 🔑 RSA DIRECT
        // =========================
        private byte[] DecryptRsaDirect(
            BinaryReader br,
            string myPrivateKeyBase64)
        {
            int len = br.ReadInt32();
            byte[] encryptedBlock = br.ReadBytes(len);

            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(
                Convert.FromBase64String(myPrivateKeyBase64),
                out _);

            return rsa.Decrypt(encryptedBlock, RSAEncryptionPadding.OaepSHA256);
        }

        // =========================
        // 🔓 SYMMETRIC CORE
        // =========================
        private byte[] DecryptSymmetricPayload(
        BinaryReader br,
        byte[] key,
        byte[] iv,
        string alg,
        string mode)
        {
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

            using var decryptor = algorithm.CreateDecryptor(key, iv);
            using var cryptoStream =
                new CryptoStream(br.BaseStream, decryptor, CryptoStreamMode.Read);
            using var ms = new MemoryStream();

            cryptoStream.CopyTo(ms);
            return ms.ToArray();
        }


        // =========================
        // 📦 PACKAGE
        // =========================
        private SecurePackage DeserializeSecurePackage(byte[] bytes)
        {
            return JsonSerializer.Deserialize<SecurePackage>(bytes)
                   ?? throw new CryptographicException("Invalid secure package");
        }

        // =========================
        // ✅ VERIFICATION
        // =========================
        private void VerifySignatureOrThrow(
            SecurePackage package,
            string producerPublicKeyBase64)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(
                Convert.FromBase64String(producerPublicKeyBase64),
                out _);

            var dataToVerify = package.Data.Concat(package.Mac).ToArray();

            bool valid = rsa.VerifyData(
                dataToVerify,
                package.Signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            if (!valid)
                throw new CryptographicException("Invalid Signature");
        }

        private void VerifyMacOrThrow(SecurePackage package, string symmetricKeyBase64)
        {
            byte[] key = Convert.FromBase64String(symmetricKeyBase64);
            using var hmac = new HMACSHA256(key);
            var resultMac = hmac.ComputeHash(package.Data);

            if (!CryptographicOperations.FixedTimeEquals(resultMac, package.Mac))
                throw new CryptographicException("MAC mismatch (tampered)");
        }

        // =========================
        // 💾 SAVE
        // =========================
        private void SaveDecryptedFile(string encryptedPath, byte[] data)
        {
            var outPath = encryptedPath.Replace(".enc", "");
            File.WriteAllBytes(outPath, data);
        }

        #endregion


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
