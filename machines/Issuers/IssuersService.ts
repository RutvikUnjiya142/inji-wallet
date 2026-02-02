import NetInfo from '@react-native-community/netinfo';
import {NativeModules} from 'react-native';
import Cloud from '../../shared/CloudBackupAndRestoreUtils';
import getAllConfigurations, {CACHED_API} from '../../shared/api';
import {
  fetchKeyPair,
  generateKeyPair,
} from '../../shared/cryptoutil/cryptoUtil';
import {
  constructProofJWT,
  hasKeyPair,
  updateCredentialInformation,
  verifyCredentialData,
} from '../../shared/openId4VCI/Utils';
import VciClient from '../../shared/vciClient/VciClient';
import {displayType, issuerType} from './IssuersMachine';
import {setItem} from '../store';
import {API_CACHED_STORAGE_KEYS} from '../../shared/constants';
import {createCacheObject} from '../../shared/Utils';
import {VerificationResult} from '../../shared/vcjs/verifyCredential';

export const IssuersService = () => {
  return {
    isUserSignedAlready: () => async () => {
      return await Cloud.isSignedInAlready();
    },
    downloadIssuersList: async () => {
      const trustedIssuersList = await CACHED_API.fetchIssuers();
      return trustedIssuersList;
    },
    checkInternet: async () => await NetInfo.fetch(),
    downloadIssuerWellknown: async (context: any) => {
      const wellknownResponse =
        (await VciClient.getInstance().getIssuerMetadata(
          context.selectedIssuer.credential_issuer_host,
        )) as issuerType;
      if (wellknownResponse) {
        const wellknownCacheObject = createCacheObject(wellknownResponse);
        await setItem(
          API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(
            context.selectedIssuer.credential_issuer_host,
          ),
          wellknownCacheObject,
          '',
        );
      }

      return wellknownResponse;
    },
    getCredentialTypes: async (context: any) => {
      const credentialTypes: Array<{id: string; [key: string]: any}> = [];
      const selectedIssuer = context.selectedIssuer;

      const keys = Object.keys(
        selectedIssuer.credential_configurations_supported,
      );

      for (const key of keys) {
        if (selectedIssuer.credential_configurations_supported[key]) {
          credentialTypes.push({
            id: key,
            ...selectedIssuer.credential_configurations_supported[key],
          });
        }
      }

      if (credentialTypes.length === 0) {
        throw new Error(
          `No credential type found for issuer ${selectedIssuer.issuer_id}`,
        );
      }
      return credentialTypes;
    },

    downloadCredential: (context: any) => async (sendBack: any) => {
      const navigateToAuthView = (authorizationEndpoint: string) => {
        sendBack({
          type: 'AUTH_ENDPOINT_RECEIVED',
          authEndpoint: authorizationEndpoint,
        });
      };
      const getProofJwt = async (
        credentialIssuer: string,
        cNonce: string | null,
        proofSigningAlgosSupported: string[] | null,
      ) => {
        sendBack({
          type: 'PROOF_REQUEST',
          credentialIssuer: credentialIssuer,
          cNonce: cNonce,
          proofSigningAlgosSupported: proofSigningAlgosSupported,
        });
      };
      const getTokenResponse = (tokenRequest: object) => {
        sendBack({
          type: 'TOKEN_REQUEST',
          tokenRequest: tokenRequest,
        });
      };
      const {credential} =
        await VciClient.getInstance().requestCredentialFromTrustedIssuer(
          context.selectedIssuer.credential_issuer_host,
          context.selectedCredentialType.id,
          {
            clientId: context.selectedIssuer.client_id,
            redirectUri: context.selectedIssuer.redirect_uri,
          },
          getProofJwt,
          navigateToAuthView,
          getTokenResponse,
        );
      return updateCredentialInformation(context, credential);
    },
    sendTxCode: async (context: any) => {
      await VciClient.getInstance().sendTxCode(context.txCode);
    },

    sendConsentGiven: async () => {
      await VciClient.getInstance().sendIssuerConsent(true);
    },

    sendConsentNotGiven: async () => {
      await VciClient.getInstance().sendIssuerConsent(false);
    },

    checkIssuerIdInStoredTrustedIssuers: async (context: any) => {
      const {RNSecureKeystoreModule} = NativeModules;
      try {
        return await RNSecureKeystoreModule.hasAlias(
          context.credentialOfferCredentialIssuer,
        );
      } catch (error) {
        console.error(
          `Error while checking issuer ID in trusted issuers:`,
          error,
        );
        return false;
      }
    },
    addIssuerToTrustedIssuers: async (context: any) => {
      const {RNSecureKeystoreModule} = NativeModules;
      try {
        await RNSecureKeystoreModule.storeData(
          context.credentialOfferCredentialIssuer,
          'trusted',
        );
      } catch {
        console.error('Error updating issuer trust in keystore');
      }
    },
    downloadCredentialFromOffer: (context: any) => async (sendBack: any) => {
      const navigateToAuthView = (authorizationEndpoint: string) => {
        sendBack({
          type: 'AUTH_ENDPOINT_RECEIVED',
          authEndpoint: authorizationEndpoint,
        });
      };
      const getSignedProofJwt = async (
        credentialIssuer: string,
        cNonce: string | null,
        proofSigningAlgosSupported: string[] | null,
      ) => {
        sendBack({
          type: 'PROOF_REQUEST',
          cNonce: cNonce,
          issuer: credentialIssuer,
          proofSigningAlgosSupported: proofSigningAlgosSupported,
        });
      };

      const getTxCode = async (
        inputMode: string | undefined,
        description: string | undefined,
        length: number | undefined,
      ) => {
        sendBack({
          type: 'TX_CODE_REQUEST',
          inputMode: inputMode,
          description: description,
          length: length,
        });
      };

      const requesTrustIssuerConsent = async (
        credentialIssuer: string,
        issuerDisplay: object[],
      ) => {
        const issuerDisplayObject = issuerDisplay as displayType[];

        sendBack({
          type: 'TRUST_ISSUER_CONSENT_REQUEST',
          issuerDisplay: issuerDisplayObject,
          issuer: credentialIssuer,
        });
      };
      const getTokenResponse = (tokenRequest: object) => {
        sendBack({
          type: 'TOKEN_REQUEST',
          tokenRequest: tokenRequest,
        });
      };

      // If the scanned QR content is a raw JSON credential (starts with '{'
      // or is valid JSON), treat it as a direct credential and return it
      // without invoking native VCI client which expects an offer/URL.
      let qrDataString = '';
      try {
        // Handle both string and ReadableNativeMap/object types
        if (typeof context.qrData === 'string') {
          qrDataString = context.qrData;
        } else if (context.qrData && typeof context.qrData === 'object') {
          // If it's a ReadableNativeMap or plain object, stringify it
          qrDataString = JSON.stringify(context.qrData);
          console.log('QR data was object, stringified:', qrDataString);
        } else {
          qrDataString = String(context.qrData);
        }

        // Check if it looks like JSON (raw credential)
        if (qrDataString && qrDataString.trim().startsWith('{')) {
          const parsed = JSON.parse(qrDataString);
          // Heuristic: if parsed looks like a VC (has vcVer or id or credential fields)
          const looksLikeCredential = !!(
            parsed.vcVer ||
            parsed.credential ||
            parsed.id ||
            parsed['@context']
          );
          if (looksLikeCredential) {
            console.log(
              'Detected raw credential JSON in QR, processing locally',
            );
            // Extract issuer - try multiple possible fields
            const issuerValue = parsed.issuer ?? parsed.credentialIssuer ?? '';
            // For credentialIssuer, use id or construct a placeholder URL if empty
            const credentialIssuerUrl =
              issuerValue ||
              (parsed.id && typeof parsed.id === 'string'
                ? parsed.id.split('/credentials/')[0]
                : '') ||
              'local://raw-credential';

            // Check if the raw data already has credentialSubject structure
            // If not, wrap the raw data in a credentialSubject
            const hasCredentialSubject = parsed.credentialSubject !== undefined;
            const credentialData = hasCredentialSubject
              ? parsed
              : {
                  '@context': ['https://www.w3.org/2018/credentials/v1'],
                  type: ['VerifiableCredential'],
                  id: parsed.id || `urn:uuid:${Date.now()}`,
                  issuer: credentialIssuerUrl,
                  issuanceDate: new Date().toISOString(),
                  credentialSubject: parsed,
                };

            const response = {
              // Match the format expected by VciClient.requestCredentialByOffer return value
              credential: {
                credential: credentialData,
              },
              credentialConfigurationId: parsed.vcVer || 'RawCredential',
              credentialIssuer: credentialIssuerUrl,
              // Mark this as a raw credential for downstream handling
              isRawCredential: true,
            };
            console.log(
              'Raw credential response:',
              JSON.stringify(response, null, 2),
            );
            return response;
          }
        }
      } catch (e) {
        // If parsing fails, continue to call native flow below.
        console.error('QR data processing error:', e);
      }

      const credentialResponse =
        await VciClient.getInstance().requestCredentialByOffer(
          qrDataString,
          getTxCode,
          getSignedProofJwt,
          navigateToAuthView,
          getTokenResponse,
          requesTrustIssuerConsent,
        );
      return credentialResponse;
    },
    sendTokenRequest: async (context: any) => {
      const tokenRequestObject = context.tokenRequestObject;
      return await sendTokenRequest(
        tokenRequestObject,
        context.selectedIssuer?.token_endpoint,
      );
    },
    sendTokenResponse: async (context: any) => {
      const tokenResponse = context.tokenResponse;
      if (!tokenResponse) {
        throw new Error(
          'Could not send token response, tokenResponse is undefined or null',
        );
      }
      return await VciClient.getInstance().sendTokenResponse(
        JSON.stringify(tokenResponse),
      );
    },

    updateCredential: async (context: any) => {
      console.log('updateCredential: context.credential =', context.credential);
      if (!context.credential) {
        console.error('updateCredential: credential is undefined in context');
        throw new Error('Credential is undefined');
      }
      const credential = await updateCredentialInformation(
        context,
        context.credential,
      );
      return credential;
    },
    cacheIssuerWellknown: async (context: any) => {
      const credentialIssuer = context.credentialOfferCredentialIssuer;

      // For raw credentials (scanned from QR without VCI flow), skip wellknown fetch
      // and return minimal issuer metadata
      if (
        context.isRawCredential ||
        !credentialIssuer ||
        credentialIssuer.startsWith('local://')
      ) {
        const mockIssuerMetadata = {
          credential_issuer: credentialIssuer || 'local://raw-credential',
          credential_endpoint: '',
          credential_configurations_supported: {
            [context.credentialConfigurationId || 'RawCredential']: {
              format: 'ldp_vc',
              display: [
                {
                  name: 'Raw Credential',
                  locale: 'en',
                },
              ],
            },
          },
          display: [
            {
              name: 'Raw Credential Issuer',
              locale: 'en',
            },
          ],
        } as unknown as issuerType;
        return mockIssuerMetadata;
      }

      const issuerMetadata = (await VciClient.getInstance().getIssuerMetadata(
        credentialIssuer,
      )) as issuerType;
      if (issuerMetadata) {
        const wellknownCacheObject = createCacheObject(issuerMetadata);
        await setItem(
          API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(credentialIssuer),
          wellknownCacheObject,
          '',
        );
      }
      return issuerMetadata;
    },
    constructProof: async (context: any) => {
      const proofJWT = await constructProofJWT(
        context.publicKey,
        context.privateKey,
        context.credentialOfferCredentialIssuer,
        null,
        context.keyType,
        context.wellknownKeyTypes,
        true,
        context.cNonce,
      );
      await VciClient.getInstance().sendProof(proofJWT);
      return proofJWT;
    },
    constructAndSendProofForTrustedIssuers: async (context: any) => {
      const issuerMeta = context.selectedIssuer;
      const proofJWT = await constructProofJWT(
        context.publicKey,
        context.privateKey,
        context.selectedIssuer.credential_issuer_host,
        context.selectedIssuer.client_id,
        context.keyType,
        context.wellknownKeyTypes,
        false,
        context.cNonce,
      );
      await VciClient.getInstance().sendProof(proofJWT);
      return proofJWT;
    },

    getKeyOrderList: async () => {
      const {RNSecureKeystoreModule} = NativeModules;
      const keyOrder = JSON.parse(
        (await RNSecureKeystoreModule.getData('keyPreference'))[1],
      );
      return keyOrder;
    },

    generateKeyPair: async (context: any) => {
      const keypair = await generateKeyPair(context.keyType);
      return keypair;
    },

    getKeyPair: async (context: any) => {
      if (context.keyType === '') {
        throw new Error('key type not found');
      } else if (!!(await hasKeyPair(context.keyType))) {
        return await fetchKeyPair(context.keyType);
      }
    },

    getSelectedKey: async (context: any) => {
      return context.keyType;
    },

    verifyCredential: async (context: any): Promise<VerificationResult> => {
      const {
        isCredentialOfferFlow,
        isRawCredential,
        verifiableCredential,
        selectedCredentialType,
      } = context;

      // Skip verification for raw credentials (JSON scanned from QR without VCI flow)
      // as they don't have cryptographic proofs
      if (isRawCredential) {
        console.log('Skipping verification for raw credential');
        return {
          isVerified: true,
          verificationMessage: 'Raw credential - verification skipped',
          verificationErrorCode: '',
        };
      }

      if (isCredentialOfferFlow) {
        const configurations = await getAllConfigurations();
        if (configurations.disableCredentialOfferVcVerification) {
          return {
            isVerified: true,
            verificationMessage: '',
            verificationErrorCode: '',
          };
        }
      }
      const verificationResult = await verifyCredentialData(
        verifiableCredential?.credential,
        selectedCredentialType.format,
      );
      if (!verificationResult.isVerified) {
        throw new Error(verificationResult.verificationErrorCode);
      }

      return verificationResult;
    },
  };
};
async function sendTokenRequest(
  tokenRequestObject: any,
  proxyTokenEndpoint: any = null,
) {
  if (proxyTokenEndpoint) {
    tokenRequestObject.tokenEndpoint = proxyTokenEndpoint;
  }
  if (!tokenRequestObject?.tokenEndpoint) {
    console.error('tokenEndpoint is not provided in tokenRequestObject');
    throw new Error('tokenEndpoint is required');
  }

  const formBody = new URLSearchParams();

  formBody.append('grant_type', tokenRequestObject.grantType);

  if (tokenRequestObject.authCode) {
    formBody.append('code', tokenRequestObject.authCode);
  }
  if (tokenRequestObject.preAuthCode) {
    formBody.append('pre-authorized_code', tokenRequestObject.preAuthCode);
  }
  if (tokenRequestObject.txCode) {
    formBody.append('tx_code', tokenRequestObject.txCode);
  }
  if (tokenRequestObject.clientId) {
    formBody.append('client_id', tokenRequestObject.clientId);
  }
  if (tokenRequestObject.redirectUri) {
    formBody.append('redirect_uri', tokenRequestObject.redirectUri);
  }
  if (tokenRequestObject.codeVerifier) {
    formBody.append('code_verifier', tokenRequestObject.codeVerifier);
  }
  const response = await fetch(tokenRequestObject.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: formBody.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error(
      'Token request failed with status:',
      response.status,
      errorText,
    );
    throw new Error(`Token request failed: ${response.status} ${errorText}`);
  }
  const tokenResponse = await response.json();
  return tokenResponse;
}
