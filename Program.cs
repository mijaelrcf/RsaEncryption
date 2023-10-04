using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;

static X509Certificate2 GetCertificate(string serialNumber)
{
    X509Store my = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    my.Open(OpenFlags.ReadOnly);
    X509Certificate2Collection collection = my.Certificates.Find(X509FindType.FindBySerialNumber, serialNumber, false);
    if (collection.Count == 1)
    {
        return collection[0];
    }
    else if (collection.Count > 1)
    {
        throw new Exception(string.Format("More than one certificate with name '{0}' found in store LocalMachine/My.", serialNumber));
    }
    else
    {
        throw new Exception(string.Format("Certificate '{0}' not found in store LocalMachine/My.", serialNumber));
    }
}

static string EncryptRsa(string content)
{
    string encryptedContent = string.Empty;

    X509Certificate2 cert = GetCertificate("2dc3d369fbf17c934b7e9424807e1ee8");

    using (var rsa = cert.GetRSAPrivateKey())
    {
        byte[] bytesData = Encoding.UTF8.GetBytes(content);
        byte[] bytesEncrypted = rsa!.Encrypt(bytesData, RSAEncryptionPadding.OaepSHA1);
        encryptedContent = Convert.ToBase64String(bytesEncrypted);
    }

    return encryptedContent;
}

static string DecryptRsa(string encrypted)
{
    string decryptedContent = string.Empty;

    X509Certificate2 cert = GetCertificate("2dc3d369fbf17c934b7e9424807e1ee8");

    using (var rsa = cert.GetRSAPrivateKey())
    {
        byte[] bytesEncrypted = Convert.FromBase64String(encrypted);
        byte[] bytesDecrypted = rsa!.Decrypt(bytesEncrypted, RSAEncryptionPadding.OaepSHA1);
        decryptedContent = Encoding.UTF8.GetString(bytesDecrypted);
    }

    return decryptedContent;
}

// Main program
Console.WriteLine("Enter your content to encrypt . . .");
var content = Console.ReadLine();

if (!string.IsNullOrEmpty(content))
{
    string cypher = EncryptRsa(content);
    Console.WriteLine();
    Console.WriteLine(" ----------------");
    Console.WriteLine("| Cypher content |");
    Console.WriteLine(" ----------------");
    Console.WriteLine(cypher);
    Console.WriteLine();

    Console.Write("Press enter to decrypt . . .");
    Console.ReadLine();
    string plainText = DecryptRsa(cypher);
    Console.WriteLine(" -------------------");
    Console.WriteLine("| Decrypted content |");
    Console.WriteLine(" -------------------");
    Console.WriteLine(plainText);    
}
else
{
    Console.WriteLine("Error: content is null or empty.");
}