/**
 * How to access metadata service data.
 * 
 * url: download from metadata service's endpoint URL
 * file: read from metadata service jwt file's path
 * jwt: use jwt string in args
 */
type AccessMds = 'url' | 'file' | 'jwt';

/**
 * How to access metadata service's root certificate.
 * 
 * url: download from root certificate's endpoint URL.
 * file: read from root certificate DER file's path.
 * pem: use pem string in args.
 */
type AccessRootCertificate = 'url' | 'file' | 'pem';

/**
 * This module's config.
 */
interface FidoMds3Config {
  mdsUrl: URL;
  mdsFile: string;
  mdsJwt?: string;
  payloadFile: string;
  rootUrl: URL;
  rootFile: string;
  rootPem?: string;

  accessMds: AccessMds;
  accessRootCertificate: AccessRootCertificate;
}

/**
 * Specify behavior refreshing metadata payload when finding authenticator info.
 * 
 * needed: if metadata payload is old, refresh data.
 * force: always refresh data.
 * error: if metadata payload is old, throw error.
 */
type FM3RefreshOption = 'needed' | 'force' | 'error';

/**
 * The metadataStatement JSON object.
 * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys
 */
interface FM3MetadataStatement {
  /**
   * The legalHeader, which must be in each Metadata Statement, is an indication of the acceptance of the relevant legal agreement for using the MDS.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-legalheader
   */
  legalHeader?: string;

  /**
   * The Authenticator Attestation ID. See [UAFProtocol] for the definition of the AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
   * 
   * Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.<br/>
   * Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.<br/>
   * Note: FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-aaid
   */
  aaid?: string;

  /**
   * The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the definition of the AAGUID structure. This field MUST be set if the authenticator implements FIDO2.
   * 
   * Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.<br/>
   * Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.<br/>
   * Note: FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-aaguid
   */
  aaguid?: string;

  /**
   * A list of the attestation certificate public key identifiers encoded as hex string.
   * 
   * Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.<br/>
   * Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.<br/>
   * Note: FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationcertificatekeyidentifiers
   */
  attestationCertificateKeyIdentifiers?: string[];

  /**
   * A human-readable, short description of the authenticator, in English.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-description
   */
  description: string;

  /**
   * A list of human-readable short descriptions of the authenticator in different languages.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-alternativedescriptions
   */
  alternativeDescriptions?:  { [languageCode: string] : string };

  /**
   * Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorversion
   */
  authenticatorVersion: number;

  /**
   * The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-protocolfamily
   */
  protocolFamily: 'uaf' | 'u2f' | 'fido2';

  /**
   * The Metadata Schema version.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-schema
   */
  schema: number;

  /**
   * The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-upv
   */
  upv: { 
    major: number, 
    minor: number 
  }[];

  /**
   * The list of authentication algorithms supported by the authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticationalgorithms
   */
  authenticationAlgorithms: string[];

  /**
   * The list of public key formats supported by the authenticator during registration operations.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-publickeyalgandencodings
   */
  publicKeyAlgAndEncodings: string[];

  /**
   * Must be set to the complete list of the supported ATTESTATION_ constant case-sensitive string names.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationtypes
   */
  attestationTypes: string[];

  /**
   * A list of alternative VerificationMethodANDCombinations.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-userverificationdetails
   */
  userVerificationDetails: {

    /**
     * a single USER_VERIFY constant case-sensitive string name.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-userverificationmethod
     */
    userVerificationMethod?: string;

    /**
     * May optionally be used in the case of method USER_VERIFY_PASSCODE_INTERNAL or USER_VERIFY_PASSCODE_EXTERNAL.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-cadesc
     */
    caDesc?: {
      /**
       * The numeric system base (radix) of the code, e.g. 10 in the case of decimal digits.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-base
       */
      base: number;

      /**
       * The minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-minlength
       */
      minLength: number;

      /**
       * Maximum number of false attempts before the authenticator will block this method (at least for some time).
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-maxretries
       */
      maxRetries?: number;

      /**
       * Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-blockslowdown
       */
      blockSlowdown?: number;
    };

    /**
     * May optionally be used in the case of method USER_VERIFY_FINGERPRINT_INTERNAL, USER_VERIFY_VOICEPRINT_INTERNAL, USER_VERIFY_FACEPRINT_INTERNAL, USER_VERIFY_EYEPRINT_INTERNAL, or USER_VERIFY_HANDPRINT_INTERNAL.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-badesc
     */
    baDesc?: {

      /**
       * The false rejection rate [ISOIEC-19795-1] for a single template, i.e. the percentage of verification transactions with truthful claims of identity that are incorrectly denied.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-selfattestedfrr
       */
      selfAttestedFRR?: number;

      /**
       * The false acceptance rate [ISOIEC-19795-1] for a single template, i.e. the percentage of verification transactions with wrongful claims of identity that are incorrectly confirmed.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-selfattestedfar
       */
      selfAttestedFAR?: number;

      /**
       * Maximum number of alternative templates from different fingers allowed (for other modalities, multiple parts of the body that can be used interchangeably), e.g. 3 if the user is allowed to enroll up to 3 different fingers to a fingerprint based authenticator.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-maxtemplates
       */
      maxTemplates?: number;

      /**
       * Maximum number of false attempts before the authenticator will block this method (at least for some time).
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-maxretries
       */
      maxRetries?: number;

      /**
       * Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-blockslowdown
       */
      blockSlowdown?: number;
    }

    /**
     * May optionally be used in case of method USER_VERIFY_PATTERN_INTERNAL or USER_VERIFY_PATTERN_EXTERNAL.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-padesc
     */
    paDesc?: {

      /**
       * Number of possible patterns (having the minimum length) out of which exactly one would be the right one, i.e. 1/probability in the case of equal distribution.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-patternaccuracydescriptor-mincomplexity
       */
      minComplexity: number;

      /**
       * Maximum number of false attempts before the authenticator will block authentication using this method (at least temporarily). 0 means it will never block.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-patternaccuracydescriptor-maxretries
       */
      maxRetries?: number;

      /**
       * Enforced minimum number of seconds wait time after blocking (due to forced reboot or similar mechanism). 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded. All alternative user verification methods MUST be specified appropriately in the metadata under userVerificationDetails.
       * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-patternaccuracydescriptor-blockslowdown
       */
      blockSlowdown?: number;
    };
  }[];

  /**
   * The list of key protection types supported by the authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-keyprotection
   */
  keyProtection: string[];

  /**
   * This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
   * This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-iskeyrestricted
   */
  isKeyRestricted?: boolean;

  /**
   * This entry is set to true, if Uauth key usage always requires a fresh user verification.
   * This entry is set to false, if the Uauth key can be used without requiring a fresh user verification.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-isfreshuserverificationrequired
   */
  isFreshUserVerificationRequired?: boolean;

  /**
   * The list of matcher protections supported by the authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-matcherprotection
   */
  matcherProtection: string[];

  /**
   * The authenticator’s overall claimed cryptographic strength in bits (sometimes also called security strength or security level).
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-cryptostrength
   */
  cryptoStrength?: number;

  /**
   * The list of supported attachment hints describing the method(s) by which the authenticator communicates with the FIDO user device.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attachmenthint
   */
  attachmentHint?: string[];

  /**
   * The list of supported transaction confirmation display capabilities.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplay
   */
  tcDisplay: string[];

  /**
   * Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaycontenttype
   */
  tcDisplayContentType?: string;

  /**
   * A list of alternative DisplayPNGCharacteristicsDescriptor.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-width
   */
  tcDisplayPNGCharacteristics?: {

    /**
     * image width
     * @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-DisplayPNGCharacteristicsDescriptor-width
     */
    width: number;

    /**
    * image height
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-height
    */
    height: number;

    /**
    * Bit depth - bits per sample or per palette index.
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-bitdepth
    */
    bitDepth: number;

    /**
    * Color type defines the PNG image type.
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-colortype
    */
    colorType: number;

    /**
    * Compression method used to compress the image data.
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-compression
    */
    compression: number;

    /**
    * Filter method is the preprocessing method applied to the image data before compression.
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-filter
    */
    filter: number;

    /**
    * Interlace method is the transmission order of the image data.
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-interlace
    */
    interlace: number;

    /**
    * 1 to 256 palette entries
    * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-plte
    */
    plte?: {
      /**
      * Red channel sample value
      * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-rgbpaletteentry-r
      */
      r: number

      /**
      * Green channel sample value
      * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-rgbpaletteentry-g
      */
      g: number;

      /**
      * Blue channel sample value
      * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-rgbpaletteentry-b
      */
      b: number;
    }[];
  }[];

  /**
   * List of attestation trust anchors for the batch chain in the authenticator attestation. Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationrootcertificates
   */
  attestationRootCertificates: string[];

  /**
   * A list of trust anchors used for ECDAA attestation.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-ecdaatrustanchors
   */
  ecdaaTrustAnchors?: {
    /**
     * base64url encoding of the result of ECPoint2ToB of the ECPoint2 \(X = P_2^x\).
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-x
     */
    X: string;

    /**
     * base64url encoding of the result of ECPoint2ToB of the ECPoint2 \(Y = P_2^y\).
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-y
     */
    Y: string;

    /**
     * base64url encoding of the result of BigNumberToB(\(c\)).
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-c
     */
    c: string;

    /**
     * base64url encoding of the result of BigNumberToB(\(sx\)).
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-sx
     */
    sx: string;

    /**
     * base64url encoding of the result of BigNumberToB(\(sy\)).
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-sy
     */
    sy: string;

    /**
     * Name of the Barreto-Naehrig elliptic curve for G1. "BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-g1curve
     */
    G1Curve: string;
  }[];

  /**
   * A data: url [RFC2397] encoded [PNG] icon for the Authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-icon
   */
  icon?: string;

  /**
   * List of extensions supported by the authenticator.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-supportedextensions
   */
  supportedExtensions?: {

    /**
     * Identifies the extension.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-id
     */
    id: string;

    /**
     * The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-tag
     */
    tag?: number;

    /**
     * Contains arbitrary data further describing the extension and/or data needed to correctly process the extension.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-data
     */
    data?: string;

    /**
     * Indicates whether unknown extensions must be ignored (false) or must lead to an error (true) when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
     * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-fail_if_unknown
     */
    fail_if_unknown: boolean;
  }[];

  /**
   * Describes supported versions, extensions, AAGUID of the device and its capabilities.
   * @see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo
   * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
   */
  authenticatorGetInfo?: {
    /**
     * List of supported versions. Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators and "U2F_V2" for CTAP1/U2F authenticators.
     */
    version: string[];

    /**
     * List of supported extensions.
     */
    extensions?: string[];

    /**
     * The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].
     */
    aaguid: string[];

    /**
     * List of supported options.
     */
    options?: {
      /**
       * platform device: Indicates that the device is attached to the client and therefore can’t be removed and used on another client.
       * Default false.
       */
      plat?: boolean;

      /**
       * resident key: Indicates that the device is capable of storing keys on the device itself and therefore can satisfy the authenticatorGetAssertion request with allowList parameter not specified or empty.
       * Default false.
       */
      rk?: boolean;

      /**
       * Client PIN: Client PIN is one of the ways to do user verification.
       * 
       * If present and set to true, it indicates that the device is capable of accepting a PIN from the client and PIN has been set.
       * If present and set to false, it indicates that the device is capable of accepting a PIN from the client and PIN has not been set yet.
       * If absent, it indicates that the device is not capable of accepting a PIN from the client.
       * Default not supported.
       */
      clientPin?: boolean;

      /**
       * user presence: Indicates that the device is capable of testing user presence.
       * Default true.
       */
      up?: boolean;

      /**
       * user verification: Indicates that the device is capable of verifying the user within itself. For example, devices with UI, biometrics fall into this category.
       * 
       * If present and set to true, it indicates that the device is capable of user verification within itself and has been configured.
       * If present and set to false, it indicates that the device is capable of user verification within itself and has not been yet configured. For example, a biometric device that has not yet been configured will return this parameter set to false.
       * If absent, it indicates that the device is not capable of user verification within itself.
       * Default not supported.
       */
      uv?: boolean;

      /**
       * Other options.
       */ 
      [option: string]: boolean | undefined;
    }

  };
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
  effectiveDate?: string;

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
  'NOT_FIDO_CERTIFIED' |
  'FIDO_CERTIFIED' |
  'USER_VERIFICATION_BYPASS' |
  'ATTESTATION_KEY_COMPROMISE' |
  'USER_KEY_REMOTE_COMPROMISE' |
  'USER_KEY_PHYSICAL_COMPROMISE' |
  'UPDATE_AVAILABLE' |
  'REVOKED' |
  'SELF_ASSERTION_SUBMITTED' |
  'FIDO_CERTIFIED_L1' |
  'FIDO_CERTIFIED_L1plus' |
  'FIDO_CERTIFIED_L2' |
  'FIDO_CERTIFIED_L2plus' |
  'FIDO_CERTIFIED_L3' |
  'FIDO_CERTIFIED_L3plus';

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
  effectiveDate?: string;

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

export {
  FidoMds3Config,
  FM3RefreshOption,
  FM3MetadataStatement,
  FM3BiometricStatusReport,
  FM3AuthenticatorStatus,
  FM3StatusReport,
  FM3MetadataBLOBPayloadEntry,
};
