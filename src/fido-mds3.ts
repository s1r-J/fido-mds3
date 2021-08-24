import fs from 'fs';
import path from 'path';
import appRoot from 'app-root-path';
import axios from 'axios';
import base64url from 'base64url';
import jose from 'jsrsasign';
import moment from 'moment';
import {
  pki,
} from 'node-forge';
import {
  parse,
} from 'comment-json';

/**
 * This module's config.
 */
interface FidoMds3Config {
  mdsUrl: URL;
  mdsFile: string;
  payloadFile: string;
  rootUrl: URL;
  rootFile: string;
}

/**
 * The metadataStatement JSON object.
 * 
 * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#metadata-keys
 */
interface FM3MetadataStatement {
  /**
   * The legalHeader, if present, contains a legal guide for accessing and using metadata.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-legalHeader
   */
  legalHeader?: string;

  /**
   * The Authenticator Attestation ID.
   * 
   * Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.<br/>
   * Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.<br/>
   * Note: FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-aaid
   */
  aaid?: string;

  /**
   * The Authenticator Attestation GUID.
   * 
   * Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.<br/>
   * Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.<br/>
   * Note: FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-aaguid
   */
  aaguid?: string;

  /**
   * A list of the attestation certificate public key identifiers encoded as hex string. 
   * 
   * Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.<br/>
   * Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.<br/>
   * Note: FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-attestationCertificateKeyIdentifiers
   */
  attestationCertificateKeyIdentifiers?: string[];

  /**
   * A human-readable, short description of the authenticator, in English.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-description
   */
  description: string;

  /**
   * A list of human-readable short descriptions of the authenticator in different languages.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-alternativeDescriptions
   */
  alternativeDescriptions?:  { [languageCode: string] : string };

  /**
   * Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-authenticatorVersion
   */
  authenticatorVersion: number;

  /**
   * The FIDO protocol family.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-protocolFamily
   */
  protocolFamily?: 'uaf' | 'u2f' | 'fido2';

  /**
   * The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-upv
   */
  upv: { 
    major: number, 
    minor: number 
  }[];

  /**
   * The assertion scheme supported by the authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-assertionScheme
   */
  assertionScheme: string;

  /**
   * The preferred authentication algorithm supported by the authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-authenticationAlgorithm
   */
  authenticationAlgorithm: number;

  /**
   * The list of authentication algorithms supported by the authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-authenticationAlgorithms
   */
  authenticationAlgorithms?: number[];

  /**
   * The preferred public key format used by the authenticator during registration operations.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-publicKeyAlgAndEncoding
   */
  publicKeyAlgAndEncoding: number;

  /**
   * The list of public key formats supported by the authenticator during registration operations.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-publicKeyAlgAndEncodings
   */
  publicKeyAlgAndEncodings?: number[];

  /**
   * The supported attestation type(s).
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-attestationTypes
   */
  attestationTypes: number[];

  /**
   * A list of alternative VerificationMethodANDCombinations.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-userVerificationDetails
   */
  userVerificationDetails: any[];

  /**
   * A 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-keyProtection
   */
  keyProtection: number;

  /**
   * This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
   * This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-isKeyRestricted
   */
  isKeyRestricted?: boolean;

  /**
   * This entry is set to true, if Uauth key usage always requires a fresh user verification.
   * This entry is set to false, if the Uauth key can be used without requiring a fresh user verification.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-isFreshUserVerificationRequired
   */
  isFreshUserVerificationRequired?: boolean;

  /**
   * A 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-matcherProtection
   */
  matcherProtection: number;

  /**
   * The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level).
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-cryptoStrength
   */
  cryptoStrength?: number;

  /**
   * Description of the particular operating environment that is used for the Authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-operatingEnv
   */
  operatingEnv?: string;

  /**
   * A 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-attachmentHint
   */
  attachmentHint: number;

  /**
   * Indicates if the authenticator is designed to be used only as a second factor, i.e. requiring some other authentication method as a first factor (e.g. username+password).
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-isSecondFactorOnly
   */
  isSecondFactorOnly: boolean;

  /**
   * A 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-tcDisplay
   */
  tcDisplay: number;

  /**
   * Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-tcDisplayContentType
   */
  tcDisplayContentType?: string;

  /**
   * A list of alternative DisplayPNGCharacteristicsDescriptor.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-tcDisplayPNGCharacteristics
   */
  tcDisplayPNGCharacteristics?: {

    /**
     * image width
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-width
     */
    width: number;

    /**
     * image height
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-height
     */
    height: number;

    /**
     * Bit depth - bits per sample or per palette index.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-bitDepth
     */
    bitDepth: number;

    /**
     * Color type defines the PNG image type.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-colorType
     */
    colorType: number;

    /**
     * Compression method used to compress the image data.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-compression
     */
    compression: number;

    /**
     * Filter method is the preprocessing method applied to the image data before compression.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-filter
     */
    filter: number;

    /**
     * Interlace method is the transmission order of the image data.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-interlace
     */
    interlace: number;

    /**
     * 1 to 256 palette entries
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-plte
     */
    pite?: {
      /**
       * Red channel sample value
       * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-rgbPaletteEntry-r
       */
      r: number

      /**
       * Green channel sample value
       * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-rgbPaletteEntry-g
       */
      g: number;

      /**
       * Blue channel sample value
       * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-rgbPaletteEntry-b
       */
      b: number;
    }
  }[];

  /**
   * Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-attestationRootCertificates
   */
  attestationRootCertificates: string[];

  /**
   * A list of trust anchors used for ECDAA attestation.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-ecdaaTrustAnchors
   */
  ecdaaTrustAnchors?: {
    /**
     * base64url encoding of the result of ECPoint2ToB of the ECPoint2 X = P_2^x.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-EcdaaTrustAnchor-X
     */
    X: string;

    /**
     * base64url encoding of the result of ECPoint2ToB of the ECPoint2 Y = P_2^y.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-EcdaaTrustAnchor-Y
     */
    Y: string;

    /**
     * base64url encoding of the result of BigNumberToB(cc).
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-EcdaaTrustAnchor-c
     */
    c: string;

    /**
     * base64url encoding of the result of BigNumberToB(sxsx).
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-EcdaaTrustAnchor-sx
     */
    sx: string;

    /**
     * base64url encoding of the result of BigNumberToB(sysy).
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-EcdaaTrustAnchor-sy
     */
    sy: string;

    /**
     * Name of the Barreto-Naehrig elliptic curve for G1. "BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-EcdaaTrustAnchor-GCurve
     */
    G1Curve: string;
  }[];

  /**
   * A data: url [RFC2397] encoded PNG [PNG] icon for the Authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-icon
   */
  icon?: string;

  /**
   * List of extensions supported by the authenticator.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-supportedExtensions
   */
  'supportedExtensions[]'?: {
    id: string;
    tag?: number;
    data?: string;
    fail_if_unknown: boolean;
  }[];
}

/**
 * Contains the current BiometricStatusReport of one of the authenticator’s biometric component.
 * 
 * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary
 */
interface FM3BiometricStatusReport {
  /**
   * Achieved level of the biometric certification of this biometric component of the authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certlevel
   */
  certLevel: number;

  /**
   * A single a single USER_VERIFY short form case-sensitive string name constant, representing biometric modality.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-modality
   */
  modality: string;

  /**
   * ISO-8601 formatted date since when the certLevel achieved, if applicable.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-effectivedate
   */
  effectiveData?: string;

  /**
   * Describes the externally visible aspects of the Biometric Certification evaluation.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificationdescriptor
   */
  certificationDescriptor?: string;

  /**
   * The unique identifier for the issued Biometric Certification.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificatenumber
   */
  certificateNumber?: string;

  /**
   * The version of the Biometric Certification Policy the implementation is certified to.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificationpolicyversion
   */
  certificationPolicyVersion?: string;

  /**
   * The version of the Biometric Requirements [FIDOBiometricsRequirements] the implementation is certified to.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificationrequirementsversion
   */
  certificationRequirementsVersion?: string;
}

/**
 * This enumeration describes the status of an authenticator model as identified by its AAID/AAGUID or attestationCertificateKeyIdentifiers and potentially some additional information.
 * 
 * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum
 */
type FM3AuthenticatorStatus = 
  "NOT_FIDO_CERTIFIED" |
  "FIDO_CERTIFIED" |
  "USER_VERIFICATION_BYPASS" |
  "ATTESTATION_KEY_COMPROMISE" |
  "USER_KEY_REMOTE_COMPROMISE" |
  "USER_KEY_PHYSICAL_COMPROMISE" |
  "UPDATE_AVAILABLE" |
  "REVOKED" |
  "SELF_ASSERTION_SUBMITTED" |
  "FIDO_CERTIFIED_L1" |
  "FIDO_CERTIFIED_L1plus" |
  "FIDO_CERTIFIED_L2" |
  "FIDO_CERTIFIED_L2plus" |
  "FIDO_CERTIFIED_L3" |
  "FIDO_CERTIFIED_L3plus";

/**
 * Contains an AuthenticatorStatus and additional data associated with it, if any.
 * New StatusReport entries will be added to report known issues present in firmware updates.
 * The latest StatusReport entry MUST reflect the "current" status.
 * 
 * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary
 */
interface FM3StatusReport {

  /**
   * Status of the authenticator. Additional fields MAY be set depending on this value.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-status
   */
  status: FM3AuthenticatorStatus;

  /**
   * ISO-8601 formatted date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-effectivedate
   */
  effectiveData?: string;

  /**
   * The authenticatorVersion that this status report relates to.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-authenticatorversion
   */
  authenticatorVersion?: number;

  /**
   * Base64-encoded [RFC4648] (not base64url!) DER [ITU-X690-2008] PKIX certificate value related to the current status, if applicable.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificate
   */
  certificate?: string;

  /**
   * HTTPS URL where additional information may be found related to the current status, if applicable.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-url
   */
  url?: string;

  /**
   * Describes the externally visible aspects of the Authenticator Certification evaluation.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationdescriptor
   */
  certificationDescriptor?: string;

  /**
   * The unique identifier for the issued Certification.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificatenumber
   */
  certificateNumber?: string;

  /**
   * The version of the Authenticator Certification Policy the implementation is Certified to.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationpolicyversion
   */
  certificationPolicyVersion?: string;

  /**
   * The Document Version of the Authenticator Security Requirements (DV) [FIDOAuthenticatorSecurityRequirements] the implementation is certified to.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationrequirementsversion
   */
  certificationRequirementsVersion?: string;
}

/**
 * MetadataBLOBPayloadEntry.
 * 
 * Example
 * ```
 *  {
 *    "aaid": "1234#5678",
 *    "metadataStatement": "Metadata Statement object as defined in Metadata Statement spec.",
 *    "statusReports": [
 *      {
 *        "status": "FIDO_CERTIFIED",
 *        "effectiveDate": "2014-01-04"
 *      }
 *    ],
 *    "timeOfLastStatusChange": "2014-01-04"
 *  }
 * ```
 * 
 * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary
 */
interface FM3MetadataBLOBPayloadEntry {
  /**
   * The AAID of the authenticator this metadata BLOB payload entry relates to.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-aaid
   */
  aaid?: string;

  /**
   * The Authenticator Attestation GUID.
   * This field MUST be set if the authenticator implements FIDO2.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-aaguid
   */
  aaguid?: string;

  /**
   * A list of the attestation certificate public key identifiers encoded as hex string.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-attestationcertificatekeyidentifiers
   */
  attestationCertificateKeyIdentifiers?: string[];

  /**
   * The metadataStatement JSON object.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-metadatastatement
   */
  metadataStatement? : FM3MetadataStatement;

  /**
   * Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-biometricstatusreports
   */
  biometricStatusReports?: FM3BiometricStatusReport[];

  /**
   * An array of status reports applicable to this authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-statusreports
   */
  statusReports: FM3StatusReport[];
  
  /**
   * ISO-8601 formatted('YYYY-MM-DD') date since when the status report array was set to the current value.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-timeoflaststatuschange
   */
  timeOfLastStatusChange: string;

  /**
   * URL of a list of rogue (i.e. untrusted) individual authenticators.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-roguelisturl
   */
  rogueListURL: string;

  /**
   * The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-roguelisthash
   */
  rogueListHash: string;
}

class FM3BaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FM3BaseError';
  }
}

/**
 * Parameter is invalid.
 */
class FM3InvalidParameterError extends FM3BaseError {
  constructor(message: string) {
    super(message);
    this.name = 'FM3InvalidParameterError';
  }
}

/**
 * Setting(default configure, file download, file save or certification validation) is invalid.
 */
class FM3SettingError extends FM3BaseError {
  constructor(message: string) {
    super(message);
    this.name = 'FM3SettingError';
  }
}

class Client {

  private config: FidoMds3Config;
  legalHeader? : string;
  updatedAt?: Date;
  no?: number;
  nextUpdateAt?: Date;
  entries?: FM3MetadataBLOBPayloadEntry[];

  constructor(config: FidoMds3Config) {
    this.config = config;
    this.load();
  }

  async refresh() {
    const mdsFileResponse = await axios.get(this.config.mdsUrl.toString());
    fs.writeFileSync(this.config.mdsFile, mdsFileResponse.data, 'utf-8');

    this.verifyCertification(mdsFileResponse.data);

    this.parse(mdsFileResponse.data);
  }

  private async verifyCertification(blobJwt: string) {
    const [header, payload, signature] = blobJwt.split('.');
    if (!header || !payload || !signature) {
      throw new FM3SettingError('Blob file does not have three dot.');
    }

    const headerJSON = JSON.parse(base64url.decode(header));
    const x5cArray = headerJSON['x5c'];
    const certKeysPki = []
    const certKeys = [];
    for (let x5c of x5cArray) {
      let certKeyString = ['-----BEGIN CERTIFICATE-----', x5c, "-----END CERTIFICATE-----"].join('\n');
      certKeysPki.push(pki.certificateFromPem(certKeyString));
      let certKey = jose.X509.getPublicKeyFromCertPEM(certKeyString);
      let certKeyPem = jose.KEYUTIL.getPEM(certKey);
      certKeys.push(certKeyPem);
    }

    const alg = headerJSON['alg'];
    const isValid = jose.KJUR.jws.JWS.verifyJWT(blobJwt, certKeys[0], {alg: [alg]});
    if (!isValid) {
      throw new FM3SettingError('JWS cannot be verified.');
    }

    // verify certificate chain
    // [ssl - Using node.js to verify a X509 certificate with CA cert - Stack Overflow](https://stackoverflow.com/questions/48377731/using-node-js-to-verify-a-x509-certificate-with-ca-cert)
    const rootCrtResponse = await axios.get(this.config.rootUrl.toString());
    fs.writeFileSync(this.config.rootFile, rootCrtResponse.data, 'utf-8');
    const cert = pki.certificateFromPem(rootCrtResponse.data);
    const caStore = pki.createCaStore([ ...certKeysPki, cert ]);
    const result = pki.verifyCertificateChain(caStore, [ cert ]);
    if (!result) {
      throw new FM3SettingError('Certificate chain cannot be verified.');
    }
  }

  private async parse(blobJwt: string) {
    const [, payload,] = blobJwt.split('.');
    const payloadString = base64url.decode(payload);
    const payloadJSON = JSON.parse(payloadString);
    fs.writeFileSync(this.config.payloadFile, payloadString, 'utf-8');

    this.format(payloadJSON);
    
    this.updatedAt = moment().toDate();
  }

  private format(payloadJSON: any) {
    this.legalHeader = payloadJSON['legalHeader'];
    this.no = payloadJSON['no'];
    this.nextUpdateAt = moment.utc(payloadJSON['nextUpdate'], 'YYYY-MM-DD').toDate();
    const entriesJSONArray = payloadJSON['entries'];

    this.entries = [];
    for (let ent of entriesJSONArray) {
      this.entries.push(ent as FM3MetadataBLOBPayloadEntry); // XXX danger
    }
  }

  private async load() {
    const payloadJSON = JSON.parse(fs.readFileSync(this.config.payloadFile, 'utf-8'));
    this.format(payloadJSON);
  }

  /**
   * Find FIDO2 authenticator by AAGUID.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
   * 
   * @param aaguid FIDO2 authenticator AAGUID
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date
   * @returns Metadata entry if not find return null
   */
  async findByAAGUID(aaguid: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!aaguid) {
      throw new FM3InvalidParameterError('"aaguid" is empty.');
    }

    if (refresh || !this.entries || (this.nextUpdateAt && moment(this.nextUpdateAt).isBefore(moment()))) {
      await this.refresh();
    }
    if (!this.entries) {
      throw new FM3SettingError('Metadata cannot be fetched.');
    }

    for (let ent of this.entries) {
      if (ent.aaguid === aaguid) {
        return ent;
      } else {
        let ms = ent.metadataStatement;
        if (ms && ms.aaguid === aaguid) {
          return ent;
        }
      }
    }

    return null;
  }

  /**
   * Find FIDO UAF authenticator by AAID.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
   * 
   * @param aaid FIDO UAF authenticator AAID
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date.
   * @returns Metadata entry if not find return null
   */
  async findByAAID(aaid: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!aaid) {
      throw new FM3InvalidParameterError('"aaid" is empty.');
    }

    if (refresh || !this.entries || (this.nextUpdateAt && moment(this.nextUpdateAt).isBefore(moment()))) {
      await this.refresh();
    }
    if (!this.entries) {
      throw new FM3SettingError('Metadata cannot be fetched.');
    }

    for (let ent of this.entries) {
      if (ent.aaid === aaid) {
        return ent;
      } else {
        let ms = ent.metadataStatement;
        if (ms && ms.aaid === aaid) {
          return ent;
        }
      }
    }

    return null;
  }

  /**
   * Find FIDO U2F authenticator by AttestationCertificateKeyIdentifier.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
   * 
   * @param attestationCertificateKeyIdentifier FIDO U2F authenticator AttestationCertificateKeyIdentifier
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date
   * @returns Metadata entry if not find return null
   */
  async findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!attestationCertificateKeyIdentifier) {
      throw new FM3InvalidParameterError('"attestationCertificateKeyIdentifiers" is empty.');
    }

    if (refresh || !this.entries || (this.nextUpdateAt && moment(this.nextUpdateAt).isBefore(moment()))) {
      await this.refresh();
    }
    if (!this.entries) {
      throw new FM3SettingError('Metadata cannot be fetched.');
    }

    for (let ent of this.entries) {
      if (!ent.attestationCertificateKeyIdentifiers) {
        continue;
      }

      if (ent.attestationCertificateKeyIdentifiers.some(aki => aki === attestationCertificateKeyIdentifier)) {
        return ent;
      } else {
        let ms = ent.metadataStatement;
        if (ms && ms.attestationCertificateKeyIdentifiers && ms.attestationCertificateKeyIdentifiers.some(aki => aki === attestationCertificateKeyIdentifier)) {
          return ent;
        }
      }
    }

    return null;
  }

  /**
   * Find FIDO(FIDO2, FIDO UAF and FIDO U2F) authenticator.
   * 
   * @param identifier AAGUID, AAID or AttestationCertificateKeyIdentifier
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date
   * @returns Metadata entry if not find return null
   */
  async findMetadata(identifier: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    const findFunctions = [this.findByAAGUID, this.findByAAID, this.findByAttestationCertificateKeyIdentifier];
    let isAlreadyRefresh = false;
    for (let func of findFunctions) {
      let ent = await func.call(this, identifier, refresh && !isAlreadyRefresh);
      if (ent) {
        return ent;
      }

      isAlreadyRefresh = true;
    }

    return null;
  }

}

class Builder {

  private config: FidoMds3Config;

  constructor(config?: Partial<FidoMds3Config>) {
    const configJson = fs.readFileSync(path.resolve(__dirname, '../config/config.json'), 'utf-8');
    const defaultConfig = parse(configJson);

    this.config = {
      mdsUrl:  (config && config.mdsUrl) || new URL(defaultConfig.mds.url),
      mdsFile: (config && config.mdsFile) || path.resolve(__dirname, defaultConfig.mds.file),
      payloadFile: (config && config.payloadFile) || path.resolve(__dirname, defaultConfig.payload.file),
      rootUrl: (config && config.rootUrl) || new URL(defaultConfig.root.url),
      rootFile: (config && config.rootFile) || path.resolve(__dirname, defaultConfig.root.file),
    };
  }

  mdsUrl(mdsUrl: URL): Builder {
    if (!mdsUrl) {
      throw new FM3InvalidParameterError('"mdsUrl" is empty.');
    }
    this.config.mdsUrl = mdsUrl;

    return this;
  }

  mdsFile(mdsFile: string): Builder {
    if (!mdsFile) {
      throw new FM3InvalidParameterError('"mdsFile" is empty.');
    }
    this.config.mdsFile = mdsFile;

    return this;
  }

  payloadFile(payloadFile: string): Builder {
    if (!payloadFile) {
      throw new FM3InvalidParameterError('"payloadFile" is empty.');
    }
    this.config.payloadFile = payloadFile;

    return this;
  }

  rootUrl(rootUrl: URL): Builder {
    if (!rootUrl) {
      throw new FM3InvalidParameterError('"rootUrl" is empty.');
    }
    this.config.rootUrl = rootUrl;

    return this;
  }

  rootFile(rootFile: string): Builder {
    if (!rootFile) {
      throw new FM3InvalidParameterError('"rootFile" is empty.');
    }
    this.config.rootFile = rootFile;

    return this;
  }

  build(): Client {
    return new Client(this.config);
  }
}

const FidoMds3 = {
  Builder,
  Client,
  FM3InvalidParameterError,
  FM3SettingError,
};

export default FidoMds3;
