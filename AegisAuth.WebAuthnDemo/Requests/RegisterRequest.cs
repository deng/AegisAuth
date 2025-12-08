using Fido2NetLib;

namespace AegisAuth.WebAuthnDemo.Requests;

// DTOs
public class RegisterRequest
{
    public required AuthenticatorAttestationRawResponse Attestation { get; set; }
    public required CredentialCreateOptions OriginalOptions { get; set; }
    public required string PublicKey { get; set; }
}