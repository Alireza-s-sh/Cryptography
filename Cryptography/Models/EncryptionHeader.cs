using Cryptography.Enums;

namespace Cryptography.Models
{
    public class EncryptionHeader
    {
        public int Version { get; set; } = 1;
        public EncryptionMethod Method { get; set; }
    }
}
