namespace Cryptography.Models
{
    public class KeyModel
    {
        public string Algorithm { get; set; } = "RSA";
        public int KeySize { get; set; } = 2048;
        public string PublicKey { get; set; } = "";
        public string PrivateKey { get; set; } = "";
        public DateTime CreatedAt { get; set; }
    }
}
