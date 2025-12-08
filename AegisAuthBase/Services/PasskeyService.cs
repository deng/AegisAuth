using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Options;

namespace AegisAuthBase.Services;

public class PasskeyService : IPasskeyService
{
    private readonly IFido2 _fido2;
    private readonly IUserPasskeyRepository _passkeyRepository;
    private readonly Fido2Configuration _fido2Config;

    public PasskeyService(
        IFido2 fido2,
        IUserPasskeyRepository passkeyRepository,
        IOptions<Fido2Configuration> fido2Config)
    {
        _fido2 = fido2;
        _passkeyRepository = passkeyRepository;
        _fido2Config = fido2Config.Value;
    }

    public async Task<CredentialCreateOptions> GetRegisterOptionsAsync(User user)
    {
        var existingKeys = (await _passkeyRepository.GetByUserIdAsync(user.Id))
            .Select(k => new PublicKeyCredentialDescriptor(Convert.FromBase64String(k.CredentialId)))
            .ToList();

        var userEntity = new Fido2User
        {
            DisplayName = user.UserName,
            Name = user.UserName,
            Id = Encoding.UTF8.GetBytes(user.Id) 
        };

        // 1. Get options
        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = userEntity,
            ExcludeCredentials = existingKeys,
            AuthenticatorSelection = AuthenticatorSelection.Default,
            AttestationPreference = AttestationConveyancePreference.None,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    Eval = new AuthenticationExtensionsPRFValues
                    {
                        First = Encoding.UTF8.GetBytes("default_salt")
                    }
                }
            }
        });
        return options;
    }

    public async Task RegisterAsync(User user, AuthenticatorAttestationRawResponse attestation, CredentialCreateOptions originalOptions)
    {
        // 2. Create credential
        var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestation,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = async (args, cancellationToken) =>
            {
                // Check if credential ID is unique
                var exists = await _passkeyRepository.GetByCredentialIdAsync(Convert.ToBase64String(args.CredentialId));
                return exists == null;
            }
        }, CancellationToken.None);

        var newPasskey = new UserPasskey
        {
            UserId = user.Id,
            CredentialId = Convert.ToBase64String(result.Id), 
            PublicKey = Convert.ToBase64String(result.PublicKey),
            SignatureCounter = result.SignCount,
            CredentialType = UserPasskeyCredentialType.PublicKey, 
            Aaguid = result.AaGuid.ToString(),
            PrfEnabled = attestation.ClientExtensionResults?.PRF?.Enabled ?? false,
            PrfFirst = attestation.ClientExtensionResults?.PRF?.Results?.First != null ? Convert.ToBase64String(attestation.ClientExtensionResults.PRF.Results.First) : null,
            PrfSecond = attestation.ClientExtensionResults?.PRF?.Results?.Second != null ? Convert.ToBase64String(attestation.ClientExtensionResults.PRF.Results.Second) : null,
            CreatedAt = DateTime.UtcNow,
            LastUsedAt = DateTime.UtcNow,
            DisplayName = "Passkey" 
        };

        await _passkeyRepository.AddAsync(newPasskey);
    }

    public async Task<AssertionOptions> GetLoginOptionsAsync(User user)
    {
        var existingKeys = (await _passkeyRepository.GetByUserIdAsync(user.Id))
            .Select(k => new PublicKeyCredentialDescriptor(Convert.FromBase64String(k.CredentialId)))
            .ToList();

        if (!existingKeys.Any())
        {
            throw new Exception("No passkeys found for this user.");
        }

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = existingKeys,
            UserVerification = UserVerificationRequirement.Preferred,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    Eval = new AuthenticationExtensionsPRFValues
                    {
                        First = Encoding.UTF8.GetBytes("default_salt")
                    }
                }
            }
        });

        return options;
    }

    public async Task<bool> LoginAsync(User user, AuthenticatorAssertionRawResponse assertion, AssertionOptions originalOptions)
    {
        // 1. Get the credential from DB
        // assertion.RawId is usually the credential ID
        var passkey = await _passkeyRepository.GetByCredentialIdAsync(Convert.ToBase64String(assertion.RawId)); 
        
        if (passkey == null || passkey.UserId != user.Id)
        {
            return false;
        }

        // 2. Verify
        var res = await _fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertion,
            OriginalOptions = originalOptions,
            StoredPublicKey = Convert.FromBase64String(passkey.PublicKey),
            StoredSignatureCounter = passkey.SignatureCounter,
            IsUserHandleOwnerOfCredentialIdCallback = (args, cancellationToken) =>
            {
                return Task.FromResult(true); 
            }
        }, CancellationToken.None);

        // 3. Update counter
        await _passkeyRepository.UpdateCounterAsync(passkey.Id, res.SignCount, DateTime.UtcNow);
        return true;
    }
}
