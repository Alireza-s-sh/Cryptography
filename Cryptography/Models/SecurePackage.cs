namespace Cryptography.Models
{
    public class SecurePackage
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public byte[] Mac { get; set; } = Array.Empty<byte>();
        public byte[] Signature { get; set; } = Array.Empty<byte>();
    }
}
